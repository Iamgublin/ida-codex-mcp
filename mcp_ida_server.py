import sys
import os
import json
import socket
import traceback
import time
import re


LOG_FILE = r"C:\temp\ida_mcp.log"

IDA_HOST = os.getenv("IDA_HOST", "127.0.0.1")
IDA_PORT = int(os.getenv("IDA_PORT", "31337"))


def _parse_target_endpoint(endpoint: str):
    endpoint = (endpoint or "").strip()
    if ":" not in endpoint:
        return None, None, "missing host:port separator"
    host, port_text = endpoint.rsplit(":", 1)
    host = host.strip()
    if not host:
        return None, None, "empty host"
    try:
        port = int(port_text.strip())
    except Exception:
        return None, None, f"invalid port '{port_text}'"
    if port <= 0 or port > 65535:
        return None, None, f"port out of range '{port}'"
    return host, port, None


def _load_targets():
    targets = {}
    warnings = []

    raw_targets = os.getenv("IDA_TARGETS", "").strip()
    if raw_targets:
        for idx, raw_item in enumerate(raw_targets.split(";"), start=1):
            item = raw_item.strip()
            if not item:
                continue

            alias = None
            endpoint = item
            if "=" in item:
                alias_part, endpoint_part = item.split("=", 1)
                alias = alias_part.strip()
                endpoint = endpoint_part.strip()
            elif not targets:
                alias = "default"
            else:
                alias = f"target_{idx}"

            if not alias:
                warnings.append(f"invalid target entry '{item}': empty alias")
                continue

            host, port, err = _parse_target_endpoint(endpoint)
            if err:
                warnings.append(f"invalid target entry '{item}': {err}")
                continue

            targets[alias] = (host, port)

    if not targets:
        targets["default"] = (IDA_HOST, IDA_PORT)

    default_target = (os.getenv("IDA_DEFAULT_TARGET", "default") or "default").strip()
    if default_target not in targets:
        warnings.append(
            f"IDA_DEFAULT_TARGET '{default_target}' not found, fallback to first target"
        )
        default_target = next(iter(targets))

    return targets, default_target, warnings


IDA_TARGETS, IDA_DEFAULT_TARGET, IDA_TARGET_WARNINGS = _load_targets()
IDA_ACTIVE_TARGET = IDA_DEFAULT_TARGET


def _parse_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _parse_float_env(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _parse_bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


IDA_DISCOVERY_HOST = os.getenv("IDA_DISCOVERY_HOST", "127.0.0.1").strip() or "127.0.0.1"
IDA_DISCOVERY_PORT_START = _parse_int_env("IDA_DISCOVERY_PORT_START", 31337)
IDA_DISCOVERY_PORT_END = _parse_int_env("IDA_DISCOVERY_PORT_END", 31437)
IDA_AUTO_DISCOVER_ON_START = _parse_bool_env("IDA_AUTO_DISCOVER_ON_START", True)
IDA_DISCOVERY_CACHE_FILE = os.getenv("IDA_DISCOVERY_CACHE_FILE", r"C:\temp\ida_mcp_targets_cache.json")
IDA_STARTUP_DISCOVERY_MIN_INTERVAL_SEC = _parse_int_env("IDA_STARTUP_DISCOVERY_MIN_INTERVAL_SEC", 30)
IDA_STARTUP_DISCOVERY_TIMEOUT_SEC = _parse_float_env("IDA_STARTUP_DISCOVERY_TIMEOUT_SEC", 4.0)
IDA_STARTUP_DISCOVERY_STOP_AFTER_MISSES = _parse_int_env("IDA_STARTUP_DISCOVERY_STOP_AFTER_MISSES", 6)
IDA_DISCOVERY_CONNECT_TIMEOUT_MS = _parse_int_env("IDA_DISCOVERY_CONNECT_TIMEOUT_MS", 15)
IDA_DISCOVERY_RETRY_TIMEOUT_MS = _parse_int_env("IDA_DISCOVERY_RETRY_TIMEOUT_MS", 1200)
if IDA_DISCOVERY_PORT_START > IDA_DISCOVERY_PORT_END:
    IDA_DISCOVERY_PORT_START, IDA_DISCOVERY_PORT_END = IDA_DISCOVERY_PORT_END, IDA_DISCOVERY_PORT_START

# alias -> metadata
IDA_TARGET_META = {}
for _alias in IDA_TARGETS:
    IDA_TARGET_META[_alias] = {
        "source": "configured",
        "info": {},
        "last_seen": None,
        "last_error": None,
    }


# ---------- logging: force UTF-8 on stderr ----------
def log(msg: str):
    # stderr 给 codex：一定是 utf-8
    try:
        sys.stderr.buffer.write((msg + "\n").encode("utf-8"))
        sys.stderr.flush()
    except Exception:
        pass
    # 本地文件你自己看
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass


# ---------- talk to IDA bridge ----------
def _sanitize_alias(name: str) -> str:
    alias = re.sub(r"[^0-9a-zA-Z_-]+", "_", (name or "").strip()).strip("_")
    if not alias:
        alias = "ida"
    if alias[0].isdigit():
        alias = f"ida_{alias}"
    return alias


def _unique_alias(alias: str) -> str:
    base = _sanitize_alias(alias)
    if base not in IDA_TARGETS:
        return base
    idx = 2
    while f"{base}_{idx}" in IDA_TARGETS:
        idx += 1
    return f"{base}_{idx}"


def _find_alias_by_endpoint(host: str, port: int):
    for alias, endpoint in IDA_TARGETS.items():
        if endpoint == (host, port):
            return alias
    return None


def _ensure_meta(alias: str):
    return IDA_TARGET_META.setdefault(
        alias,
        {"source": "discovered", "info": {}, "last_seen": None, "last_error": None},
    )


def _effective_route_target(explicit_target: str = None):
    if explicit_target:
        explicit_target = explicit_target.strip()
        if explicit_target in IDA_TARGETS:
            return explicit_target
        return None
    if IDA_ACTIVE_TARGET in IDA_TARGETS:
        return IDA_ACTIVE_TARGET
    if IDA_DEFAULT_TARGET in IDA_TARGETS:
        return IDA_DEFAULT_TARGET
    if IDA_TARGETS:
        return next(iter(IDA_TARGETS))
    return None


def _is_local_loopback_host(host: str) -> bool:
    host = (host or "").strip().lower()
    return host in ("127.0.0.1", "localhost", "::1")


def _tcp_port_open(host: str, port: int, timeout_ms: int = 15) -> bool:
    timeout_sec = max(0.003, float(timeout_ms) / 1000.0)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout_sec)
        return s.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _error_text(result) -> str:
    if isinstance(result, dict):
        return str(result.get("error", ""))
    return ""


def _is_unknown_method_error(message: str) -> bool:
    msg = (message or "").lower()
    return "unknown method" in msg or "method not found" in msg


def _is_timeout_like_error(message: str) -> bool:
    msg = (message or "").lower()
    return "timed out" in msg or "timeout" in msg


def _socket_request(host: str, port: int, method: str, params: dict, timeout: float = 5.0):
    log(f"[ida-mcp] -> IDA raw request[{host}:{port}] {method} {params}")
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        # 防止连接成功但对端迟迟不回包导致阻塞
        s.settimeout(timeout)
    except OSError as e:
        err = {"error": f"connect ida {host}:{port} failed: {e}"}
        log(f"[ida-mcp] <- IDA error(connect): {err}")
        return err

    try:
        payload = json.dumps({"method": method, "params": params}, ensure_ascii=True) + "\n"
        s.sendall(payload.encode("utf-8"))

        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk:
                break
    except (OSError, TimeoutError) as e:
        s.close()
        err = {"error": f"socket io failed for {host}:{port}: {e}"}
        log(f"[ida-mcp] <- IDA error(io): {err}")
        return err

    s.close()
    if not data:
        err = {"error": "empty reply from ida"}
        log(f"[ida-mcp] <- IDA error(empty): {err}")
        return err
    text = data.decode("utf-8", "ignore").strip()
    log(f"[ida-mcp] <- IDA raw[{host}:{port}]: {text}")
    try:
        return json.loads(text)
    except Exception as e:
        err = {"error": f"bad json from ida: {e}", "raw": text}
        log(f"[ida-mcp] <- IDA error(json): {err}")
        return err


def _set_active_target(alias: str):
    global IDA_ACTIVE_TARGET
    IDA_ACTIVE_TARGET = alias


def _register_target(alias: str, host: str, port: int, source: str = "discovered", info: dict = None):
    existing_alias = _find_alias_by_endpoint(host, port)
    if existing_alias:
        meta = _ensure_meta(existing_alias)
        if source == "configured" or meta.get("source") != "configured":
            meta["source"] = source
        if isinstance(info, dict):
            meta["info"] = info
        meta["last_seen"] = int(time.time())
        meta["last_error"] = None
        return existing_alias

    final_alias = _unique_alias(alias)
    IDA_TARGETS[final_alias] = (host, port)
    meta = _ensure_meta(final_alias)
    meta["source"] = source
    if isinstance(info, dict):
        meta["info"] = info
    meta["last_seen"] = int(time.time())
    meta["last_error"] = None
    return final_alias


def _derive_alias_from_info(info: dict, port: int):
    candidates = []
    if isinstance(info, dict):
        for key in ("database_name", "idb_name", "input_file_name", "input_file", "module_name"):
            value = info.get(key)
            if isinstance(value, str) and value.strip():
                candidates.append(value.strip())
    for value in candidates:
        base = os.path.basename(value)
        root, _ = os.path.splitext(base)
        root = _sanitize_alias(root or base)
        if root:
            return f"{root}_{port}"
    return f"ida_{port}"


def _probe_ida_instance(host: str, port: int, timeout_ms: int = 250, connect_timeout_ms: int = None):
    if connect_timeout_ms is None:
        if _is_local_loopback_host(host):
            connect_timeout_ms = IDA_DISCOVERY_CONNECT_TIMEOUT_MS
        else:
            connect_timeout_ms = max(50, min(timeout_ms, 300))
    connect_timeout_ms = max(3, int(connect_timeout_ms))

    # Fast TCP probe first: skip expensive JSON request for closed ports.
    if not _tcp_port_open(host, port, timeout_ms=connect_timeout_ms):
        return None

    timeout_sec = max(0.05, float(timeout_ms) / 1000.0)

    info = _socket_request(host, port, "get_instance_info", {}, timeout=timeout_sec)
    if isinstance(info, dict) and "error" not in info:
        return {
            "host": host,
            "port": port,
            "info": info,
            "legacy": False,
        }

    message = _error_text(info)
    if _is_unknown_method_error(message):
        funcs = _socket_request(host, port, "list_functions", {}, timeout=timeout_sec)
        if isinstance(funcs, list):
            return {
                "host": host,
                "port": port,
                "info": {
                    "bridge": "ida_bridge_legacy",
                    "functions_count": len(funcs),
                },
                "legacy": True,
            }
        return None

    # If the IDA UI thread is busy, first response might timeout. Retry once with longer timeout.
    if _is_timeout_like_error(message):
        retry_timeout_sec = max(timeout_sec * 3.0, float(max(200, IDA_DISCOVERY_RETRY_TIMEOUT_MS)) / 1000.0)
        info_retry = _socket_request(host, port, "get_instance_info", {}, timeout=retry_timeout_sec)
        if isinstance(info_retry, dict) and "error" not in info_retry:
            return {
                "host": host,
                "port": port,
                "info": info_retry,
                "legacy": False,
            }
        retry_message = _error_text(info_retry)
        if _is_unknown_method_error(retry_message):
            funcs = _socket_request(host, port, "list_functions", {}, timeout=retry_timeout_sec)
            if isinstance(funcs, list):
                return {
                    "host": host,
                    "port": port,
                    "info": {
                        "bridge": "ida_bridge_legacy",
                        "functions_count": len(funcs),
                    },
                    "legacy": True,
                }
    return None


def _discover_targets(
    host: str = None,
    port_start: int = None,
    port_end: int = None,
    timeout_ms: int = 250,
    prune: bool = True,
    max_duration_sec: float = None,
    stop_after_consecutive_misses: int = None,
):
    host = (host or IDA_DISCOVERY_HOST or "127.0.0.1").strip()
    try:
        port_start = int(port_start if port_start is not None else IDA_DISCOVERY_PORT_START)
        port_end = int(port_end if port_end is not None else IDA_DISCOVERY_PORT_END)
        timeout_ms = int(timeout_ms)
    except Exception:
        return {"error": "port_start, port_end and timeout_ms must be integers"}

    if timeout_ms <= 0:
        timeout_ms = 250
    if port_start > port_end:
        port_start, port_end = port_end, port_start

    if _is_local_loopback_host(host):
        connect_timeout_ms = max(3, min(50, IDA_DISCOVERY_CONNECT_TIMEOUT_MS))
    else:
        connect_timeout_ms = max(20, min(timeout_ms, 300))

    deadline = None
    if max_duration_sec is not None:
        try:
            max_duration_sec = float(max_duration_sec)
            if max_duration_sec > 0:
                deadline = time.monotonic() + max_duration_sec
        except Exception:
            deadline = None

    miss_limit = None
    if stop_after_consecutive_misses is not None:
        try:
            miss_limit = int(stop_after_consecutive_misses)
        except Exception:
            miss_limit = None
        if miss_limit is not None and miss_limit <= 0:
            miss_limit = None

    discovered = []
    discovered_endpoints = set()
    scanned_ports = 0
    consecutive_misses = 0
    truncated = False
    break_reason = None
    for port in range(port_start, port_end + 1):
        if deadline is not None and time.monotonic() >= deadline:
            truncated = True
            break_reason = "time_budget_reached"
            break

        scanned_ports += 1
        probe = _probe_ida_instance(
            host,
            port,
            timeout_ms=timeout_ms,
            connect_timeout_ms=connect_timeout_ms,
        )
        if not probe:
            consecutive_misses += 1
            if miss_limit is not None and discovered and consecutive_misses >= miss_limit:
                truncated = True
                break_reason = "consecutive_misses_reached"
                break
            continue
        consecutive_misses = 0

        info = probe.get("info", {})
        alias = _find_alias_by_endpoint(host, port)
        if not alias:
            alias = _derive_alias_from_info(info, port)
            alias = _register_target(alias, host, port, source="discovered", info=info)
        else:
            meta = _ensure_meta(alias)
            if meta.get("source") != "configured":
                meta["source"] = "discovered"
            meta["last_seen"] = int(time.time())
            meta["last_error"] = None
            if isinstance(info, dict):
                meta["info"] = info
        discovered_endpoints.add((host, port))
        discovered.append({"alias": alias, "host": host, "port": port, "info": info, "legacy": bool(probe.get("legacy"))})

    removed = []
    if prune and not truncated:
        for alias, endpoint in list(IDA_TARGETS.items()):
            meta = _ensure_meta(alias)
            if meta.get("source") == "configured":
                continue
            ep_host, ep_port = endpoint
            if ep_host == host and port_start <= ep_port <= port_end and endpoint not in discovered_endpoints:
                removed.append({"alias": alias, "host": ep_host, "port": ep_port})
                IDA_TARGETS.pop(alias, None)
                IDA_TARGET_META.pop(alias, None)

    global IDA_ACTIVE_TARGET
    if IDA_ACTIVE_TARGET not in IDA_TARGETS:
        IDA_ACTIVE_TARGET = _effective_route_target() or IDA_DEFAULT_TARGET

    result = {
        "host": host,
        "port_start": port_start,
        "port_end": port_end,
        "timeout_ms": timeout_ms,
        "connect_timeout_ms": connect_timeout_ms,
        "discovered": discovered,
        "removed": removed,
        "total_targets": len(IDA_TARGETS),
        "active_target": IDA_ACTIVE_TARGET,
        "scanned_ports": scanned_ports,
        "truncated": truncated,
        "break_reason": break_reason,
    }
    _save_discovery_cache()
    return result


def _target_items(check_live: bool = False, timeout_ms: int = 250):
    items = []
    for alias, (host, port) in sorted(IDA_TARGETS.items()):
        meta = _ensure_meta(alias)
        online = None
        error_text = meta.get("last_error")
        if check_live:
            probe = _probe_ida_instance(host, port, timeout_ms=timeout_ms)
            online = probe is not None
            if probe is not None:
                meta["last_seen"] = int(time.time())
                meta["last_error"] = None
                info = probe.get("info")
                if isinstance(info, dict):
                    meta["info"] = info
            else:
                meta["last_error"] = f"offline ({host}:{port})"
            error_text = meta.get("last_error")

        items.append(
            {
                "alias": alias,
                "host": host,
                "port": port,
                "source": meta.get("source", "unknown"),
                "is_default": alias == IDA_DEFAULT_TARGET,
                "is_active": alias == IDA_ACTIVE_TARGET,
                "last_seen": meta.get("last_seen"),
                "last_error": error_text,
                "online": online,
                "info": meta.get("info", {}),
            }
        )
    return items


def _match_name(name: str, pattern: str, mode: str, case_sensitive: bool):
    if not isinstance(name, str):
        return False
    mode = (mode or "exact").strip().lower()
    if mode not in ("exact", "contains", "regex"):
        return False
    if mode == "regex":
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.search(pattern, name, flags) is not None
        except re.error:
            return False
    if not case_sensitive:
        name_cmp = name.lower()
        pattern_cmp = pattern.lower()
    else:
        name_cmp = name
        pattern_cmp = pattern
    if mode == "exact":
        return name_cmp == pattern_cmp
    return pattern_cmp in name_cmp


def _load_discovery_cache():
    if not IDA_DISCOVERY_CACHE_FILE:
        return None
    try:
        with open(IDA_DISCOVERY_CACHE_FILE, "r", encoding="utf-8") as f:
            cache = json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        log(f"[ida-mcp] discovery cache load failed: {e}")
        return None

    items = cache.get("targets")
    if not isinstance(items, list):
        return cache

    restored = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        alias = str(item.get("alias") or "").strip()
        host = str(item.get("host") or "").strip()
        port = item.get("port")
        if not alias or not host:
            continue
        try:
            port = int(port)
        except Exception:
            continue
        if port <= 0 or port > 65535:
            continue

        source = str(item.get("source") or "discovered").strip() or "discovered"
        if source == "configured":
            continue

        if _find_alias_by_endpoint(host, port):
            continue

        final_alias = _register_target(
            alias=alias,
            host=host,
            port=port,
            source=source,
            info=item.get("info") if isinstance(item.get("info"), dict) else {},
        )
        meta = _ensure_meta(final_alias)
        if item.get("last_seen") is not None:
            try:
                meta["last_seen"] = int(item.get("last_seen"))
            except Exception:
                pass
        if item.get("last_error") is not None:
            meta["last_error"] = str(item.get("last_error"))
        restored += 1

    cached_active = cache.get("active_target")
    if isinstance(cached_active, str) and cached_active in IDA_TARGETS:
        _set_active_target(cached_active)

    log(f"[ida-mcp] discovery cache restored targets: {restored}")
    return cache


def _save_discovery_cache(updated_at: int = None):
    if not IDA_DISCOVERY_CACHE_FILE:
        return
    payload = {
        "updated_at": int(updated_at if updated_at is not None else time.time()),
        "default_target": IDA_DEFAULT_TARGET,
        "active_target": IDA_ACTIVE_TARGET,
        "targets": [],
    }
    for alias, (host, port) in sorted(IDA_TARGETS.items()):
        meta = _ensure_meta(alias)
        payload["targets"].append(
            {
                "alias": alias,
                "host": host,
                "port": port,
                "source": meta.get("source", "unknown"),
                "last_seen": meta.get("last_seen"),
                "last_error": meta.get("last_error"),
                "info": meta.get("info", {}),
            }
        )
    try:
        with open(IDA_DISCOVERY_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, indent=2)
    except Exception as e:
        log(f"[ida-mcp] discovery cache save failed: {e}")


def _should_skip_startup_discovery(cache: dict):
    if IDA_STARTUP_DISCOVERY_MIN_INTERVAL_SEC <= 0:
        return False
    if not isinstance(cache, dict):
        return False
    updated_at = cache.get("updated_at")
    try:
        updated_at = int(updated_at)
    except Exception:
        return False
    age = int(time.time()) - updated_at
    return age >= 0 and age < IDA_STARTUP_DISCOVERY_MIN_INTERVAL_SEC


def ida_request(method: str, ida_target: str = None, **params):
    explicit_target = (ida_target or "").strip()
    if explicit_target and explicit_target not in IDA_TARGETS:
        err = {
            "error": (
                f"unknown target '{explicit_target}'. "
                f"available targets: {', '.join(sorted(IDA_TARGETS.keys()))}"
            )
        }
        log(f"[ida-mcp] <- IDA error(target): {err}")
        return err

    target_name = _effective_route_target(explicit_target if explicit_target else None)
    if not target_name:
        err = {"error": "no ida targets configured"}
        log(f"[ida-mcp] <- IDA error(target): {err}")
        return err
    endpoint = IDA_TARGETS.get(target_name)
    if endpoint is None:
        err = {
            "error": (
                f"unknown target '{explicit_target}'. "
                f"available targets: {', '.join(sorted(IDA_TARGETS.keys()))}"
            )
        }
        log(f"[ida-mcp] <- IDA error(target): {err}")
        return err

    host, port = endpoint
    result = _socket_request(host, port, method, params, timeout=5.0)
    meta = _ensure_meta(target_name)
    if isinstance(result, dict) and "error" in result:
        meta["last_error"] = str(result.get("error"))
    else:
        meta["last_seen"] = int(time.time())
        meta["last_error"] = None
    return result


def request(method: str, **params):
    return ida_request(method, **params)


# ---------- safe send to stdout (must be ascii/utf-8) ----------
def safe_send(obj: dict):
    # Codex 这边最稳就是 ensure_ascii=True
    line = json.dumps(obj, ensure_ascii=True)
    log(f"[ida-mcp] -> MCP stdout: {line}")
    try:
        sys.stdout.buffer.write((line + "\n").encode("utf-8"))
        sys.stdout.flush()
    except BrokenPipeError:
        log("[ida-mcp] BrokenPipeError on send, exiting.")
        sys.exit(0)


def _inject_target_argument(tools: list):
    target_desc = (
        "Optional IDA target alias. Configure via IDA_TARGETS "
        "(example: A=127.0.0.1:31337;B=127.0.0.1:31338)."
    )
    for tool in tools:
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict):
            continue
        props = schema.setdefault("properties", {})
        if "ida_target" not in props:
            props["ida_target"] = {"type": "string", "description": target_desc}


# ---------- handlers ----------
def handle_initialize(req: dict):
    params = req.get("params") or {}
    client_proto = params.get("protocolVersion", "2024-11-05")
    log(f"[ida-mcp] initialize from client: {params}")
    resp = {
        "jsonrpc": "2.0",
        "id": req.get("id"),
        "result": {
            "protocolVersion": client_proto,
            "capabilities": {
                "tools": {},
                "resources": {},
            },
            "serverInfo": {
                "name": "ida-mcp",
                "version": "0.4.0",
            },
        },
    }
    safe_send(resp)


def handle_tools_list(req: dict):
    log("[ida-mcp] tools/list called")
    # 全部用英文描述，避免再出编码问题
    tools = [
        {
            "name": "ida_list_targets",
            "description": "List known IDA targets (configured and discovered), including active/default route",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "check_live": {
                        "type": "boolean",
                        "default": False,
                        "description": "Probe each target to verify online state"
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "default": 250,
                        "description": "Per-target probe timeout in milliseconds when check_live=true"
                    },
                },
                "required": [],
            },
        },
        {
            "name": "ida_discover_targets",
            "description": "Actively discover running IDA bridge instances by scanning localhost port range and save them as targets",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "default": "127.0.0.1",
                        "description": "Host to scan"
                    },
                    "port_start": {
                        "type": "integer",
                        "default": 31337,
                        "description": "Start port (inclusive)"
                    },
                    "port_end": {
                        "type": "integer",
                        "default": 31437,
                        "description": "End port (inclusive)"
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "default": 250,
                        "description": "Per-port timeout in milliseconds"
                    },
                    "prune": {
                        "type": "boolean",
                        "default": True,
                        "description": "Remove previously discovered targets in scanned range when no longer active"
                    },
                },
                "required": [],
            },
        },
        {
            "name": "ida_set_active_target",
            "description": "Set current active IDA target so subsequent calls can omit ida_target",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ida_target": {
                        "type": "string",
                        "description": "Target alias to set active"
                    },
                },
                "required": ["ida_target"],
            },
        },
        {
            "name": "ida_find_function_across_targets",
            "description": "Search function names across known IDA targets, optionally auto-discover first, and locate which target contains the API",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function/API name pattern to search"
                    },
                    "match_mode": {
                        "type": "string",
                        "enum": ["exact", "contains", "regex"],
                        "default": "exact",
                        "description": "Name match mode"
                    },
                    "case_sensitive": {
                        "type": "boolean",
                        "default": False,
                        "description": "Whether name matching is case-sensitive"
                    },
                    "auto_discover": {
                        "type": "boolean",
                        "default": True,
                        "description": "Run ida_discover_targets before searching"
                    },
                    "set_active_when_unique": {
                        "type": "boolean",
                        "default": True,
                        "description": "Set active target automatically when only one target has matches"
                    },
                    "max_results_per_target": {
                        "type": "integer",
                        "default": 20,
                        "description": "Max matched functions to return per target"
                    },
                },
                "required": ["name"],
            },
        },
        {
            "name": "ida_list_functions",
            "description": "List all functions from current IDA database",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "ida_call_graph",
            "description": "Get call graph from a function (depth-limited)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "max_depth": {"type": "integer", "default": 2},
                },
                "required": ["name"],
            },
        },
        {
            "name": "ida_analyze_function",
            "description": "Analyze a function to guess its role based on called functions. Returns analysis results WITHOUT renaming by default. Use ida_list_functions to get valid function names. IMPORTANT: Only set rename=true when explicitly asked to rename the function.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name to analyze (e.g., 'DriverEntry', 'sub_118C0')"
                    },
                    "max_depth": {
                        "type": "integer",
                        "default": 2,
                        "description": "Maximum depth for call graph analysis (1-3 recommended)"
                    },
                    "rename": {
                        "type": "boolean",
                        "default": False,
                        "description": "CAUTION: Set to true ONLY when user explicitly requests renaming. Default false means analysis only, no modifications to IDA database."
                    },
                    "rename_locals": {
                        "type": "boolean",
                        "default": False,
                        "description": "CAUTION: Set to true ONLY when user explicitly requests renaming local variables. Requires rename=true."
                    },
                },
                "required": ["name"],
            },
        },
        {
            "name": "ida_get_pseudocode",
            "description": "Return Hex-Rays/F5 pseudocode for a function. IMPORTANT: Use function 'name' parameter (recommended), not 'ea'. Get function names from ida_list_functions first. Supports pagination for large content.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name (RECOMMENDED - e.g., 'DriverEntry', 'sub_118C0'). Use ida_list_functions to get valid names."
                    },
                    "ea": {
                        "type": "integer",
                        "description": "Function start address in decimal (AVOID if possible - must be > 0). Use 'name' instead."
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Starting line number (0-based) for pagination. Default is 0 (from beginning).",
                        "default": 0
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of lines to return. If not specified, returns all lines. Use for pagination of large functions.",
                    },
                },
                "anyOf": [
                    {"required": ["name"]},
                    {"required": ["ea"]}
                ],
            },
        },
        {
            "name": "ida_get_disassembly",
            "description": "Return full disassembly for a function. IMPORTANT: Use function 'name' parameter (recommended), not 'ea'. Get function names from ida_list_functions first. Supports pagination for large content.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Function name (RECOMMENDED - e.g., 'DriverEntry', 'sub_118C0'). Use ida_list_functions to get valid names."
                    },
                    "ea": {
                        "type": "integer",
                        "description": "Function start address in decimal (AVOID if possible - must be > 0). Use 'name' instead."
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Starting line number (0-based) for pagination. Default is 0 (from beginning).",
                        "default": 0
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of lines to return. If not specified, returns all lines. Use for pagination of large functions.",
                    },
                },
                "anyOf": [
                    {"required": ["name"]},
                    {"required": ["ea"]}
                ],
            },
        },
        {
            "name": "ida_rename_function",
            "description": "Rename a function in IDA by old name",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "old_name": {"type": "string"},
                    "new_name": {"type": "string"},
                },
                "required": ["old_name", "new_name"],
            },
        },
        {
            "name": "ida_get_imports",
            "description": "Get all imports (imported functions from DLLs) from the IDA database",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        {
            "name": "ida_get_exports",
            "description": "Get all exports (exported functions) from the IDA database",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
        {
            "name": "ida_get_xrefs",
            "description": "Get all cross-references (xrefs) to a variable, function, or address. Shows where the target is used/called in the code.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": ["string", "integer"],
                        "description": "Target name (e.g., 'dword_5CE14', 'sub_12FA8') or address in decimal. Use ida_list_functions or ida_get_imports to find valid names."
                    },
                },
                "required": ["target"],
            },
        },
        {
            "name": "ida_list_globals",
            "description": "List all global variables/data in the IDA database (paginated). Returns named data symbols from data segments.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "description": "Starting offset for pagination (0-based)"
                    },
                    "count": {
                        "type": "integer",
                        "default": 100,
                        "description": "Maximum number of globals to return (1-1000)"
                    },
                },
                "required": [],
            },
        },
        {
            "name": "ida_read_memory",
            "description": "Read raw bytes from a specific memory address in the IDA database. Returns hex dump and ASCII representation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "integer",
                        "description": "Memory address to read from (in decimal)"
                    },
                    "size": {
                        "type": "integer",
                        "description": "Number of bytes to read (1-65536)"
                    },
                },
                "required": ["address", "size"],
            },
        },
        {
            "name": "ida_get_strings",
            "description": "List all strings found in the IDA database (paginated). Returns string content, location, type, and cross-references.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "min_length": {
                        "type": "integer",
                        "default": 4,
                        "description": "Minimum string length to include (1-255)"
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "description": "Starting offset for pagination (0-based)"
                    },
                    "count": {
                        "type": "integer",
                        "default": 100,
                        "description": "Maximum number of strings to return (1-1000)"
                    },
                },
                "required": [],
            },
        },
        {
            "name": "ida_jump_to_address",
            "description": "Jump to a specific address in IDA (similar to pressing 'g' and entering address). Useful for navigating to function pointers or data locations.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "integer",
                        "description": "Target address to jump to (in decimal)"
                    },
                },
                "required": ["address"],
            },
        },
        {
            "name": "ida_set_data_type",
            "description": "Set the data type at a specific address (byte, word, dword, qword, etc.). Similar to pressing 'D' then type key in IDA.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "integer",
                        "description": "Address to set data type for (in decimal)"
                    },
                    "data_type": {
                        "type": "string",
                        "enum": ["byte", "word", "dword", "qword", "float", "double", "ascii", "unicode"],
                        "description": "Data type to set (byte=1, word=2, dword=4, qword=8 bytes)"
                    },
                },
                "required": ["address", "data_type"],
            },
        },
        {
            "name": "ida_set_function_pointer_type",
            "description": "Set a function pointer type at a specific address (similar to pressing 'Y' in IDA). This helps Hex-Rays recognize function pointers and display proper function calls instead of MEMORY[address]. FIXED: Now supports simplified signatures.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "integer",
                        "description": "Address to set function pointer type for (in decimal)"
                    },
                    "function_signature": {
                        "type": "string",
                        "description": "Function signature. Supports simplified formats: 'NTSTATUS', 'NTSTATUS __fastcall', etc. Also accepts full signatures like 'NTSTATUS (__fastcall *)(void *a1, void *a2, int a3, int a4, int a5)'"
                    },
                },
                "required": ["address", "function_signature"],
            },
        },
        {
            "name": "ida_set_name",
            "description": "Set a name for an address (similar to pressing 'N' in IDA). INTELLIGENT: Automatically detects function pointers and sets proper QWORD data type + function pointer type, making Hex-Rays display function calls correctly instead of MEMORY[address]. Useful for naming function pointers, variables, or functions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "integer",
                        "description": "Address to name (in decimal)"
                    },
                    "name": {
                        "type": "string",
                        "description": "New name for the address (e.g., 'MmIsAddressValid', 'ExAllocatePool', 'g_ApiPointer')"
                    },
                },
                "required": ["address", "name"],
            },
        },
        {
            "name": "ida_create_function_pointer",
            "description": "Complete workflow: convert MEMORY[address] calls to named function calls. This combines jump, set qword data type, set function pointer type, and naming in one operation. FIXED: Now supports simplified signatures like 'NTSTATUS __fastcall'.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": {
                        "type": "integer",
                        "description": "Address of the function pointer (in decimal)"
                    },
                    "name": {
                        "type": "string",
                        "description": "Function name (e.g., 'PsLookupSomething')"
                    },
                    "function_signature": {
                        "type": "string",
                        "description": "Function signature. Supports simplified formats: 'NTSTATUS', 'NTSTATUS __fastcall', 'HANDLE', etc. Also accepts full signatures like 'NTSTATUS (__fastcall *)(void *, void *, int, int, int)'"
                    },
                },
                "required": ["address", "name", "function_signature"],
            },
        },
        {
            "name": "ida_py_exec",
            "description": "Execute Python code/expressions in IDA's Python interpreter. PREFERRED for calculations and simple expressions (e.g., hex conversions, address arithmetic). Returns the result or output. Use this instead of terminal commands for: hex/decimal conversions (hex(0x1234), 0x4B0894), calculations (0x1000 + 0x200), IDA API calls (idaapi.get_imagebase()), and custom analysis. Also use this tool to add pseudocode comments (via ida_hexrays API). Much faster and more reliable than running external python commands.\n\n**IMPORTANT for adding comments with non-ASCII characters (e.g., Chinese):**\n1. Code with Unicode/Chinese characters is transmitted via JSON with ensure_ascii=True, converting them to \\uXXXX escape sequences\n2. IDA Bridge decodes UTF-8 and Python correctly interprets the Unicode strings\n3. When calling idc.set_func_cmt() or cfunc.set_user_cmt(), the Unicode string is properly passed to IDA's comment system\n4. This encoding flow ensures comments with Chinese/Unicode characters work correctly across network boundaries\n5. Example: cfunc.set_user_cmt(tl, '初始化') works because the string is properly encoded/decoded through the JSON transport layer",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Python expression or code to execute in IDA. Examples: 'hex(0x4B0894)' for hex conversion, '0x1000 + 0x200' for calculation, 'idaapi.get_imagebase()' for IDA API, 'print(idc.get_func_name(0x401000))' for function info. For adding comments with Chinese/Unicode: directly include the characters in string literals - they will be automatically encoded via JSON escape sequences (\\uXXXX) during transmission and properly decoded in IDA"
                    },
                },
                "required": ["code"],
            },
        },
    ]
    _inject_target_argument(tools)
    resp = {
        "jsonrpc": "2.0",
        "id": req.get("id"),
        "result": {
            "tools": tools
        },
    }
    safe_send(resp)


def handle_tools_call(req: dict):
    params = req.get("params") or {}
    tool_name = params.get("name")
    args = params.get("arguments") or {}
    log(f"[ida-mcp] tools/call {tool_name} {args}")

    selected_target = args.get("ida_target")
    if selected_target is not None:
        selected_target = str(selected_target).strip()
        if not selected_target:
            selected_target = None

    base_request = globals()["request"]

    def request(method: str, **call_params):
        if selected_target and "ida_target" not in call_params:
            call_params["ida_target"] = selected_target
        return base_request(method, **call_params)

    def ok(text: str, meta: dict = None):
        result = {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": False,
            },
        }
        if meta:
            result["result"]["_meta"] = meta
        safe_send(result)

    def err(text: str):
        safe_send({
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {
                "content": [{"type": "text", "text": text}],
                "isError": True,
            },
        })

    try:
        if tool_name == "ida_list_targets":
            check_live = bool(args.get("check_live", False))
            try:
                timeout_ms = int(args.get("timeout_ms", 250))
            except Exception:
                err("timeout_ms must be an integer")
                return

            target_items = _target_items(check_live=check_live, timeout_ms=timeout_ms)
            lines = [
                f"Default target: {IDA_DEFAULT_TARGET}",
                f"Active target: {IDA_ACTIVE_TARGET}",
                f"Known targets: {len(target_items)}",
                "",
            ]
            for item in target_items:
                flags = []
                if item.get("is_default"):
                    flags.append("default")
                if item.get("is_active"):
                    flags.append("active")
                if item.get("online") is True:
                    flags.append("online")
                elif item.get("online") is False:
                    flags.append("offline")
                suffix = f" [{'|'.join(flags)}]" if flags else ""
                lines.append(
                    f"{item['alias']}: {item['host']}:{item['port']} source={item.get('source', 'unknown')}{suffix}"
                )
                if item.get("last_error"):
                    lines.append(f"  last_error: {item['last_error']}")
                info = item.get("info") if isinstance(item.get("info"), dict) else {}
                if info:
                    db_name = info.get("database_name") or info.get("idb_name")
                    input_name = info.get("input_file_name") or info.get("input_file")
                    if db_name or input_name:
                        lines.append(f"  db={db_name or '?'} input={input_name or '?'}")

            ok(
                "\n".join(lines),
                meta={
                    "targets": target_items,
                    "default_target": IDA_DEFAULT_TARGET,
                    "active_target": IDA_ACTIVE_TARGET,
                },
            )

        elif tool_name == "ida_discover_targets":
            host = args.get("host") or IDA_DISCOVERY_HOST
            port_start = args.get("port_start", IDA_DISCOVERY_PORT_START)
            port_end = args.get("port_end", IDA_DISCOVERY_PORT_END)
            timeout_ms = args.get("timeout_ms", 250)
            prune = bool(args.get("prune", True))

            result = _discover_targets(
                host=host,
                port_start=port_start,
                port_end=port_end,
                timeout_ms=timeout_ms,
                prune=prune,
            )
            if "error" in result:
                err("discover failed: " + result["error"])
                return

            discovered = result.get("discovered", [])
            removed = result.get("removed", [])
            lines = [
                f"Discovery range: {result.get('host')}:{result.get('port_start')}-{result.get('port_end')}",
                f"Probe timeout(ms): connect={result.get('connect_timeout_ms')} response={result.get('timeout_ms')}",
                f"Discovered active instances: {len(discovered)}",
                f"Removed stale discovered targets: {len(removed)}",
                f"Total known targets: {result.get('total_targets')}",
                f"Active target: {result.get('active_target')}",
                "",
            ]
            for item in discovered:
                legacy = " legacy=yes" if item.get("legacy") else ""
                lines.append(f"{item['alias']}: {item['host']}:{item['port']}{legacy}")
                info = item.get("info") if isinstance(item.get("info"), dict) else {}
                db_name = info.get("database_name") or info.get("idb_name")
                input_name = info.get("input_file_name") or info.get("input_file")
                if db_name or input_name:
                    lines.append(f"  db={db_name or '?'} input={input_name or '?'}")

            if removed:
                lines.append("")
                lines.append("Removed:")
                for item in removed:
                    lines.append(f"  {item['alias']}: {item['host']}:{item['port']}")

            ok("\n".join(lines), meta=result)

        elif tool_name == "ida_set_active_target":
            target_alias = args.get("ida_target")
            if not target_alias:
                err("ida_target required")
                return
            target_alias = str(target_alias).strip()
            if target_alias not in IDA_TARGETS:
                err(
                    f"unknown ida_target '{target_alias}'. "
                    f"available targets: {', '.join(sorted(IDA_TARGETS.keys()))}"
                )
                return
            _set_active_target(target_alias)
            _save_discovery_cache()
            ok(
                f"Active target set to: {target_alias}",
                meta={
                    "active_target": IDA_ACTIVE_TARGET,
                    "default_target": IDA_DEFAULT_TARGET,
                },
            )

        elif tool_name == "ida_find_function_across_targets":
            pattern = args.get("name")
            if not pattern:
                err("name required")
                return

            match_mode = str(args.get("match_mode", "exact"))
            case_sensitive = bool(args.get("case_sensitive", False))
            auto_discover = bool(args.get("auto_discover", True))
            set_active_when_unique = bool(args.get("set_active_when_unique", True))
            try:
                max_results_per_target = int(args.get("max_results_per_target", 20))
            except Exception:
                err("max_results_per_target must be an integer")
                return
            if max_results_per_target <= 0:
                max_results_per_target = 20

            discovery_meta = None
            if auto_discover:
                discovery_meta = _discover_targets(
                    host=IDA_DISCOVERY_HOST,
                    port_start=IDA_DISCOVERY_PORT_START,
                    port_end=IDA_DISCOVERY_PORT_END,
                    timeout_ms=250,
                    prune=True,
                )
                if "error" in discovery_meta:
                    err("auto_discover failed: " + discovery_meta["error"])
                    return

            target_hits = []
            target_errors = []
            for alias in sorted(IDA_TARGETS.keys()):
                funcs = request("list_functions", ida_target=alias)
                if isinstance(funcs, dict) and "error" in funcs:
                    target_errors.append({"target": alias, "error": funcs["error"]})
                    continue
                if not isinstance(funcs, list):
                    target_errors.append({"target": alias, "error": "unexpected list_functions result"})
                    continue

                matches = []
                for f in funcs:
                    name = f.get("name")
                    if _match_name(name, pattern, match_mode, case_sensitive):
                        matches.append(
                            {
                                "name": name,
                                "ea": f.get("ea"),
                            }
                        )
                    if len(matches) >= max_results_per_target:
                        break

                if matches:
                    target_hits.append(
                        {
                            "target": alias,
                            "host": IDA_TARGETS[alias][0],
                            "port": IDA_TARGETS[alias][1],
                            "match_count": len(matches),
                            "matches": matches,
                        }
                    )

            auto_selected_target = None
            if set_active_when_unique and len(target_hits) == 1:
                auto_selected_target = target_hits[0]["target"]
                _set_active_target(auto_selected_target)
                _save_discovery_cache()

            total_match_count = sum(item["match_count"] for item in target_hits)
            lines = [
                f"Pattern: {pattern}",
                f"Match mode: {match_mode}, case_sensitive={case_sensitive}",
                f"Targets scanned: {len(IDA_TARGETS)}",
                f"Targets with matches: {len(target_hits)}",
                f"Total matches (capped per target): {total_match_count}",
                "",
            ]
            for item in target_hits:
                lines.append(
                    f"{item['target']} ({item['host']}:{item['port']}): {item['match_count']} match(es)"
                )
                for m in item["matches"]:
                    ea = m.get("ea")
                    lines.append(f"  {hex(ea) if isinstance(ea, int) else '?'}: {m.get('name')}")

            if not target_hits:
                lines.append("No matches found in known targets.")

            if auto_selected_target:
                lines.append("")
                lines.append(f"Active target automatically set to: {auto_selected_target}")

            if target_errors:
                lines.append("")
                lines.append(f"Targets with errors: {len(target_errors)}")
                for item in target_errors:
                    lines.append(f"  {item['target']}: {item['error']}")

            ok(
                "\n".join(lines),
                meta={
                    "pattern": pattern,
                    "match_mode": match_mode,
                    "case_sensitive": case_sensitive,
                    "hits": target_hits,
                    "errors": target_errors,
                    "auto_selected_target": auto_selected_target,
                    "active_target": IDA_ACTIVE_TARGET,
                    "discovery": discovery_meta,
                },
            )

        elif tool_name == "ida_list_functions":
            data = request("list_functions")
            ok(json.dumps(data, ensure_ascii=True, indent=2))

        elif tool_name == "ida_call_graph":
            name = args.get("name")
            max_depth = int(args.get("max_depth", 2))
            data = request("call_graph", root_name=name, max_depth=max_depth)
            ok(json.dumps(data, ensure_ascii=True, indent=2))

        elif tool_name == "ida_analyze_function":
            name = args.get("name")
            max_depth = int(args.get("max_depth", 2))
            rename = bool(args.get("rename", False))
            rename_locals = bool(args.get("rename_locals", False))

            analysis = request("analyze_function", name=name, max_depth=max_depth)
            if "error" in analysis:
                err("analyze failed: " + analysis["error"])
                return

            roles = analysis.get("role") or []
            role_slug = roles[0] if roles else "func"
            safe_role = role_slug.replace(" ", "_").replace("/", "_")
            new_name = f"{safe_role}_{name}"

            if rename:
                ea = analysis.get("ea")
                if ea is not None:
                    request("rename_function", ea=int(ea), new_name=new_name)
                    if rename_locals:
                        request("rename_locals", ea=int(ea), names=["ctx", "arg", "tmp", "ret"])

            # 这里也用 ASCII，避免再炸
            lines = []
            lines.append(f"function {name} roles: {', '.join(roles) if roles else 'unknown'}")
            lines.append(f"depth: {max_depth}")
            if rename:
                lines.append(f"renamed to: {new_name}")
            lines.append("call_tree:")
            lines.append(json.dumps(analysis.get("call_tree", {}), ensure_ascii=True, indent=2))

            ok("\n".join(lines), meta={"analysis": analysis})

        elif tool_name == "ida_get_pseudocode":
            name = args.get("name")
            ea_arg = args.get("ea")
            offset = int(args.get("offset", 0))
            limit = args.get("limit")
            
            # Validate and filter ea
            if ea_arg is not None and ea_arg == 0:
                # If name is also provided, just ignore the invalid ea and use name
                if name:
                    log(f"[ida-mcp] Ignoring invalid ea=0, using name={name}")
                    ea_arg = None
                else:
                    err("ea cannot be 0. Provide a valid function name instead (e.g., 'DriverEntry'). Use ida_list_functions to see available functions.")
                    return
            
            if not name and ea_arg is None:
                err("name or ea required. Provide a function name (recommended) or valid address. Use ida_list_functions to get valid function names.")
                return
            
            pseudo_params = {}
            if name:
                pseudo_params["name"] = name
            if ea_arg is not None:
                try:
                    pseudo_params["ea"] = int(ea_arg)
                except Exception:
                    err("ea must be an integer")
                    return
            pseudo = request("get_pseudocode", **pseudo_params)
            if "error" in pseudo:
                err("pseudocode failed: " + pseudo["error"] + ". Try using the function name instead of EA, or verify the function exists with ida_list_functions.")
                return
            pseudo_text = pseudo.get("pseudocode")
            if not isinstance(pseudo_text, str):
                err("pseudocode not returned. The function may not be decompilable or Hex-Rays may not be available.")
                return
            
            # Apply pagination
            lines = pseudo_text.split('\n')
            total_lines = len(lines)
            
            if offset < 0:
                offset = 0
            
            # If offset is at or beyond total lines, return empty content with metadata
            if offset >= total_lines:
                paginated_lines = []
                paginated_text = ""
                end_line = offset
            else:
                if limit is not None:
                    try:
                        limit = int(limit)
                        end_line = min(offset + limit, total_lines)
                    except Exception:
                        err("limit must be an integer")
                        return
                else:
                    end_line = total_lines
                
                paginated_lines = lines[offset:end_line]
                paginated_text = '\n'.join(paginated_lines)
            
            func_name = pseudo.get("name") or name or "<unknown>"
            pseudo_ea = pseudo.get("ea") or pseudo_params.get("ea")
            header = f"function {func_name} pseudocode"
            if pseudo_ea is not None:
                header += f" (EA {hex(pseudo_ea)})"
            
            # Add pagination info to header
            if limit is not None or offset > 0:
                header += f" [lines {offset}-{end_line-1} of {total_lines}]"
            
            result_meta = {
                "pseudocode": pseudo_text,
                "analysis": pseudo,
                "pagination": {
                    "offset": offset,
                    "limit": limit,
                    "returned_lines": len(paginated_lines),
                    "total_lines": total_lines,
                    "has_more": end_line < total_lines
                }
            }
            
            ok("\n".join([header, paginated_text]), meta=result_meta)


        elif tool_name == "ida_get_disassembly":
            name = args.get("name")
            ea_arg = args.get("ea")
            offset = int(args.get("offset", 0))
            limit = args.get("limit")
            
            # Validate and filter ea
            if ea_arg is not None and ea_arg == 0:
                # If name is also provided, just ignore the invalid ea and use name
                if name:
                    log(f"[ida-mcp] Ignoring invalid ea=0, using name={name}")
                    ea_arg = None
                else:
                    err("ea cannot be 0. Provide a valid function name instead (e.g., 'DriverEntry'). Use ida_list_functions to see available functions.")
                    return
            
            if not name and ea_arg is None:
                err("name or ea required. Provide a function name (recommended) or valid address. Use ida_list_functions to get valid function names.")
                return
            
            disasm_params = {}
            if name:
                disasm_params["name"] = name
            if ea_arg is not None:
                try:
                    disasm_params["ea"] = int(ea_arg)
                except Exception:
                    err("ea must be an integer")
                    return
            disasm = request("get_disassembly", **disasm_params)
            if "error" in disasm:
                err("disassembly failed: " + disasm["error"] + ". Try using the function name instead of EA, or verify the function exists with ida_list_functions.")
                return
            disasm_text = disasm.get("disassembly")
            if not isinstance(disasm_text, str):
                err("disassembly not returned. The function may not exist.")
                return
            
            # Apply pagination
            lines = disasm_text.split('\n')
            total_lines = len(lines)
            
            if offset < 0:
                offset = 0
            
            # If offset is at or beyond total lines, return empty content with metadata
            if offset >= total_lines:
                paginated_lines = []
                paginated_text = ""
                end_line = offset
            else:
                if limit is not None:
                    try:
                        limit = int(limit)
                        end_line = min(offset + limit, total_lines)
                    except Exception:
                        err("limit must be an integer")
                        return
                else:
                    end_line = total_lines
                
                paginated_lines = lines[offset:end_line]
                paginated_text = '\n'.join(paginated_lines)
            
            func_name = disasm.get("name") or name or "<unknown>"
            header = f"function {func_name} disassembly"
            
            # Add pagination info to header
            if limit is not None or offset > 0:
                header += f" [lines {offset}-{end_line-1} of {total_lines}]"
            
            result_meta = {
                "disassembly": disasm_text,
                "analysis": disasm,
                "pagination": {
                    "offset": offset,
                    "limit": limit,
                    "returned_lines": len(paginated_lines),
                    "total_lines": total_lines,
                    "has_more": end_line < total_lines
                }
            }
            
            ok("\n".join([header, paginated_text]), meta=result_meta)

        elif tool_name == "ida_rename_function":
            old_name = args.get("old_name")
            new_name = args.get("new_name")
            funcs = request("list_functions")
            if isinstance(funcs, dict) and "error" in funcs:
                err("list_functions failed: " + funcs["error"])
                return
            target_ea = None
            for f in funcs:
                if f.get("name") == old_name:
                    target_ea = f.get("ea")
                    break
            if target_ea is None:
                err(f"function {old_name} not found")
                return
            request("rename_function", ea=int(target_ea), new_name=new_name)
            ok(f"renamed {old_name} -> {new_name}")

        elif tool_name == "ida_get_imports":
            data = request("get_imports")
            if "error" in data:
                err("get_imports failed: " + data["error"])
                return
            imports = data.get("imports", [])
            
            # 格式化输出
            lines = [f"Total imports: {len(imports)}", ""]
            
            # 按模块分组
            by_module = {}
            for imp in imports:
                module = imp.get("module", "unknown")
                if module not in by_module:
                    by_module[module] = []
                by_module[module].append(imp)
            
            for module in sorted(by_module.keys()):
                lines.append(f"Module: {module}")
                for imp in by_module[module]:
                    ea = imp.get("ea")
                    name = imp.get("name")
                    ordinal = imp.get("ordinal")
                    if ordinal:
                        lines.append(f"  {hex(ea) if ea else '?'}: {name} (ord {ordinal})")
                    else:
                        lines.append(f"  {hex(ea) if ea else '?'}: {name}")
                lines.append("")
            
            ok("\n".join(lines), meta=data)

        elif tool_name == "ida_get_exports":
            data = request("get_exports")
            if "error" in data:
                err("get_exports failed: " + data["error"])
                return
            exports = data.get("exports", [])
            
            lines = [f"Total exports: {len(exports)}", ""]
            for exp in exports:
                ea = exp.get("ea")
                name = exp.get("name")
                ordinal = exp.get("ordinal")
                lines.append(f"{hex(ea) if ea else '?'}: {name} (ordinal {ordinal})")
            
            ok("\n".join(lines), meta=data)

        elif tool_name == "ida_get_xrefs":
            target = args.get("target")
            if not target:
                err("target required")
                return
            
            data = request("get_xrefs_to", target=target)
            if "error" in data:
                err("get_xrefs failed: " + data["error"])
                return
            
            xrefs = data.get("xrefs", [])
            count = data.get("count", 0)
            target_ea = data.get("target_ea")
            target_name = data.get("target_name", str(target))
            
            lines = [
                f"Cross-references to: {target_name}",
                f"Target EA: {hex(target_ea) if target_ea else '?'}",
                f"Total references: {count}",
                ""
            ]
            
            if xrefs:
                for xref in xrefs:
                    from_ea = xref.get("from_ea")
                    ref_type = xref.get("type")
                    func = xref.get("function")
                    disasm = xref.get("disasm")
                    
                    lines.append(f"From: {hex(from_ea)} in {func}")
                    lines.append(f"  Type: {ref_type}")
                    lines.append(f"  Code: {disasm}")
                    lines.append("")
            else:
                lines.append("No references found.")
            
            ok("\n".join(lines), meta=data)

        elif tool_name == "ida_list_globals":
            offset = int(args.get("offset", 0))
            count = int(args.get("count", 100))
            
            data = request("list_globals", offset=offset, count=count)
            if "error" in data:
                err("list_globals failed: " + data["error"])
                return
            
            globals_list = data.get("globals", [])
            total = data.get("total", 0)
            has_more = data.get("has_more", False)
            
            lines = [
                f"Global Variables (showing {len(globals_list)} of {total})",
                f"Offset: {offset}, Has more: {has_more}",
                ""
            ]
            
            for g in globals_list:
                ea = g.get("ea")
                name = g.get("name")
                dtype = g.get("type")
                size = g.get("size")
                segment = g.get("segment")
                
                lines.append(f"{hex(ea)}: {name}")
                lines.append(f"  Type: {dtype}, Size: {size}, Segment: {segment}")
            
            if has_more:
                lines.append("")
                lines.append(f"Use offset={offset + count} to get next page")
            
            ok("\n".join(lines), meta=data)

        elif tool_name == "ida_read_memory":
            address = args.get("address")
            size = args.get("size")
            
            if address is None or size is None:
                err("address and size required")
                return
            
            try:
                address = int(address)
                size = int(size)
            except Exception:
                err("address and size must be integers")
                return
            
            data = request("read_memory_bytes", address=address, size=size)
            if "error" in data:
                err("read_memory failed: " + data["error"])
                return
            
            read_size = data.get("size", 0)
            hex_str = data.get("hex", "")
            ascii_str = data.get("ascii", "")
            name = data.get("name")
            
            lines = [
                f"Memory at {hex(address)}" + (f" ({name})" if name else ""),
                f"Size: {read_size} bytes",
                "",
                "Hex dump:"
            ]
            
            # 格式化十六进制输出 (16 字节一行)
            for i in range(0, len(hex_str), 32):  # 32 hex chars = 16 bytes
                chunk_hex = hex_str[i:i+32]
                # 添加空格分隔
                formatted_hex = " ".join(chunk_hex[j:j+2] for j in range(0, len(chunk_hex), 2))
                chunk_ascii = ascii_str[i//2:i//2+16]
                addr_offset = address + i//2
                lines.append(f"{hex(addr_offset)}: {formatted_hex:48s}  {chunk_ascii}")
            
            ok("\n".join(lines), meta=data)

        elif tool_name == "ida_get_strings":
            min_length = int(args.get("min_length", 4))
            offset = int(args.get("offset", 0))
            count = int(args.get("count", 100))
            
            data = request("get_strings", min_length=min_length, offset=offset, count=count)
            if "error" in data:
                err("get_strings failed: " + data["error"])
                return
            
            strings_list = data.get("strings", [])
            total = data.get("total", 0)
            has_more = data.get("has_more", False)
            
            lines = [
                f"Strings found in database (showing {len(strings_list)} of {total})",
                f"Minimum length: {min_length}, Offset: {offset}, Has more: {has_more}",
                ""
            ]
            
            for s in strings_list:
                ea = s.get("ea")
                length = s.get("length")
                content = s.get("content", "")
                str_type = s.get("type")
                xrefs_count = s.get("xrefs_count", 0)
                xrefs = s.get("xrefs", [])
                
                # 限制显示长度,避免输出太长
                display_content = content if len(content) <= 80 else content[:77] + "..."
                
                lines.append(f"{hex(ea)}: \"{display_content}\"")
                lines.append(f"  Type: {str_type}, Length: {length}, Xrefs: {xrefs_count}")
                
                if xrefs:
                    lines.append(f"  Referenced by:")
                    for xref in xrefs:
                        xref_from = xref.get("from")
                        xref_func = xref.get("function")
                        lines.append(f"    {hex(xref_from)} in {xref_func}")
                lines.append("")
            
            if has_more:
                lines.append(f"Use offset={offset + count} to get next page")
            
            ok("\n".join(lines), meta=data)

        elif tool_name == "ida_jump_to_address":
            address = args.get("address")
            if address is None:
                err("address required")
                return
            
            try:
                address = int(address)
            except Exception:
                err("address must be an integer")
                return
            
            data = request("jump_to_address", address=address)
            if "error" in data:
                err("jump_to_address failed: " + data["error"])
                return
            
            ok(f"Jumped to address {hex(address)}")

        elif tool_name == "ida_set_data_type":
            address = args.get("address")
            data_type = args.get("data_type")
            
            if address is None or data_type is None:
                err("address and data_type required")
                return
            
            try:
                address = int(address)
            except Exception:
                err("address must be an integer")
                return
            
            data = request("set_data_type", address=address, data_type=data_type)
            if "error" in data:
                err("set_data_type failed: " + data["error"])
                return
            
            ok(f"Set data type '{data_type}' at address {hex(address)}")

        elif tool_name == "ida_set_function_pointer_type":
            address = args.get("address")
            function_signature = args.get("function_signature")
            
            if address is None or function_signature is None:
                err("address and function_signature required")
                return
            
            try:
                address = int(address)
            except Exception:
                err("address must be an integer")
                return
            
            data = request("set_function_pointer_type", address=address, function_signature=function_signature)
            if "error" in data:
                err("set_function_pointer_type failed: " + data["error"])
                return
            
            ok(f"Set function pointer type at address {hex(address)}: {function_signature}")

        elif tool_name == "ida_set_name":
            address = args.get("address")
            name = args.get("name")
            
            if address is None or name is None:
                err("address and name required")
                return
            
            try:
                address = int(address)
            except Exception:
                err("address must be an integer")
                return
            
            data = request("set_name", address=address, name=name)
            if "error" in data:
                error_msg = data["error"]
                # 如果是地址未映射的错误，尝试先创建 segment
                if "is not mapped" in error_msg:
                    log(f"[ida-mcp] Address not mapped, attempting to create segment at {hex(address)}")
                    
                    # 创建 segment
                    segment_name = f"seg_{hex(address)[2:].upper()}"
                    create_result = request("create_segment", address=address, name=segment_name, size=0x10000)
                    
                    if "error" not in create_result:
                        log(f"[ida-mcp] Successfully created segment, retrying set_name")
                        # 重新尝试设置名称
                        retry_data = request("set_name", address=address, name=name)
                        if "error" in retry_data:
                            err("set_name failed after creating segment: " + retry_data["error"])
                            return
                        else:
                            ok(f"Set name '{name}' at address {hex(address)} (created segment {segment_name})")
                            return
                    else:
                        log(f"[ida-mcp] Failed to create segment: {create_result['error']}")
                        err("set_name failed: " + error_msg + " (and failed to create segment: " + create_result["error"] + ")")
                        return
                else:
                    err("set_name failed: " + error_msg)
                    return
            
            # 构建响应消息
            final_name = data.get("name", name)
            response_lines = [f"Set name '{final_name}' at address {hex(address)}"]
            
            # 添加自动处理信息
            auto_proc = data.get("auto_processing")
            if auto_proc and isinstance(auto_proc, dict):
                # 显示名称冲突处理
                if "name_conflict" in auto_proc:
                    response_lines.append(f"\n⚠ {auto_proc['name_conflict']}")
                    if "name_resolution" in auto_proc:
                        response_lines.append(f"  → Resolution: {auto_proc['name_resolution']}")
                
                # 显示指针值
                if "pointer_value" in auto_proc:
                    response_lines.append(f"\nPointer value: {auto_proc['pointer_value']}")
                
                # 显示段创建信息
                if "segment_created" in auto_proc:
                    seg_info = auto_proc["segment_created"]
                    response_lines.append(f"\n✓ Created segment for target address:")
                    response_lines.append(f"  → Segment name: {seg_info['name']}")
                    response_lines.append(f"  → Range: {seg_info['start']} - {seg_info['end']}")
                
                # 显示检测结果
                detected = auto_proc.get("detected")
                if detected and "pointer" in detected:
                    response_lines.append(f"\n✓ Auto-detected: {detected}")
                    if "target_function" in auto_proc:
                        response_lines.append(f"  → Points to function: {auto_proc['target_function']}")
                    if "data_type" in auto_proc:
                        response_lines.append(f"  → Data type set to: {auto_proc['data_type']}")
                    if "function_type" in auto_proc:
                        response_lines.append(f"  → Function type applied: {auto_proc['function_type']}")
                    response_lines.append("\n✓ Hex-Rays should now display function calls using the name instead of MEMORY[address]")
            
            ok("\n".join(response_lines), meta=data)

        elif tool_name == "ida_create_function_pointer":
            address = args.get("address")
            name = args.get("name")
            function_signature = args.get("function_signature")
            
            if address is None or name is None or function_signature is None:
                err("address, name and function_signature required")
                return
            
            try:
                address = int(address)
            except Exception:
                err("address must be an integer")
                return
            
            data = request("create_function_pointer", address=address, name=name, function_signature=function_signature)
            if "error" in data:
                err("create_function_pointer failed: " + data["error"])
                return
            
            lines = [
                f"Successfully created function pointer at {hex(address)}:",
                f"Name: {name}",
                f"Type: {function_signature}",
                "",
                "Operations performed:",
                "1. Jumped to address",
                "2. Set data type to QWORD",
                "3. Applied function pointer type",
                "4. Set name",
                "",
                "Hex-Rays should now display function calls using the name instead of MEMORY[address]."
            ]
            
            ok("\n".join(lines), meta=data)

        elif tool_name == "ida_py_exec":
            code = args.get("code")
            if not code:
                err("code parameter required")
                return
            
            data = request("py_exec", code=code)
            if "error" in data:
                err("py_exec failed: " + data["error"])
                return
            
            result = data.get("result")
            output = data.get("output", "")
            error_msg = data.get("error_msg", "")
            
            lines = []
            if output:
                lines.append("Output:")
                lines.append(output)
            
            if result is not None:
                lines.append("\nResult:")
                lines.append(str(result))
            
            if error_msg:
                lines.append("\nError:")
                lines.append(error_msg)
            
            if not lines:
                lines.append("Execution completed (no output)")
            
            ok("\n".join(lines), meta=data)

        else:
            err(f"unknown tool: {tool_name}")

    except Exception:
        err("exception:\n" + traceback.format_exc())


def _sanitize_resource_id(name: str) -> str:
    return re.sub(r"[^0-9a-zA-Z_-]+", "_", name)


def handle_resources_list(req: dict):
    log("[ida-mcp] resources/list called")
    funcs = request("list_functions")
    resources = []
    if isinstance(funcs, dict) and "error" in funcs:
        error_text = funcs["error"]
        log(f"[ida-mcp] resources/list error fetching functions: {error_text}")
        resources.append(
            {
                "uri": "ida://functions/error",
                "name": "IDA functions unavailable",
                "mimeType": "text/plain",
                "description": error_text,
            }
        )
    elif isinstance(funcs, list):
        limit = 500
        for func in funcs[:limit]:
            name = func.get("name") or "<unnamed>"
            ea = func.get("ea")
            resources.append(
                {
                    "uri": f"ida://function/{ea}/{name}",
                    "name": name,
                    "mimeType": "text/plain",
                    "description": f"IDA function at EA {hex(ea) if isinstance(ea, int) else ea}",
                }
            )
        if not resources:
            resources.append(
                {
                    "uri": "ida://functions/empty",
                    "name": "IDA functions list empty",
                    "mimeType": "text/plain",
                    "description": "IDA returned no functions yet",
                }
            )
    safe_send(
        {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {"resources": resources},
        }
    )


def handle_resources_read(req: dict):
    log("[ida-mcp] resources/read called")
    params = req.get("params") or {}
    uri = params.get("uri")
    
    if not uri:
        safe_send({
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "error": {
                "code": -32602,
                "message": "uri parameter required",
            },
        })
        return
    
    log(f"[ida-mcp] reading resource: {uri}")
    
    # Parse URI: ida://function/{ea}/{name}
    if uri.startswith("ida://function/"):
        parts = uri.replace("ida://function/", "").split("/", 1)
        if len(parts) >= 2:
            try:
                ea = int(parts[0])
                name = parts[1]
                log(f"[ida-mcp] parsed function: ea={ea}, name={name}")
                
                # Get pseudocode for this function
                pseudo = request("get_pseudocode", name=name)
                
                if "error" in pseudo:
                    # If pseudocode fails, try disassembly
                    log(f"[ida-mcp] pseudocode failed, trying disassembly")
                    disasm = request("get_disassembly", name=name)
                    if "error" in disasm:
                        safe_send({
                            "jsonrpc": "2.0",
                            "id": req.get("id"),
                            "error": {
                                "code": -32603,
                                "message": f"Failed to read function: {disasm.get('error', 'unknown error')}",
                            },
                        })
                        return
                    
                    content = disasm.get("disassembly", "")
                    content_type = "disassembly"
                else:
                    content = pseudo.get("pseudocode", "")
                    content_type = "pseudocode"
                
                # Return resource content
                safe_send({
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "text/plain",
                                "text": f"Function: {name} (EA: {hex(ea)})\nType: {content_type}\n\n{content}",
                            }
                        ]
                    },
                })
                return
                
            except (ValueError, IndexError) as e:
                log(f"[ida-mcp] failed to parse URI: {e}")
    
    # Unknown URI format
    safe_send({
        "jsonrpc": "2.0",
        "id": req.get("id"),
        "error": {
            "code": -32602,
            "message": f"Invalid or unsupported URI format: {uri}",
        },
    })


def handle_resources_templates_list(req: dict):
    log("[ida-mcp] resources/templates/list called")
    templates = [
        {
            "id": "ida_function",
            "name": "IDA Function",
            "description": "Reference to a function exported by the IDA database",
            "schema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Function name"},
                    "ea": {"type": "integer", "description": "Starting EA"},
                },
                "required": ["name", "ea"],
            },
        }
    ]
    safe_send(
        {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": {"resourceTemplates": templates},
        }
    )


def main():
    log("===== ida-mcp server started (ascii-safe) =====")
    cache = _load_discovery_cache()
    target_desc = ", ".join(
        f"{alias}={host}:{port}" for alias, (host, port) in sorted(IDA_TARGETS.items())
    )
    log(f"[ida-mcp] configured targets: {target_desc}")
    log(f"[ida-mcp] default target: {IDA_DEFAULT_TARGET}")
    log(f"[ida-mcp] active target: {IDA_ACTIVE_TARGET}")
    log(
        f"[ida-mcp] discovery range: {IDA_DISCOVERY_HOST}:{IDA_DISCOVERY_PORT_START}-{IDA_DISCOVERY_PORT_END}"
    )
    log(f"[ida-mcp] auto discover on start: {IDA_AUTO_DISCOVER_ON_START}")
    log(f"[ida-mcp] startup discovery min interval: {IDA_STARTUP_DISCOVERY_MIN_INTERVAL_SEC}s")
    log(f"[ida-mcp] startup discovery timeout budget: {IDA_STARTUP_DISCOVERY_TIMEOUT_SEC}s")
    log(f"[ida-mcp] startup discovery miss-limit: {IDA_STARTUP_DISCOVERY_STOP_AFTER_MISSES}")
    log(f"[ida-mcp] discovery connect-timeout(ms): {IDA_DISCOVERY_CONNECT_TIMEOUT_MS}")
    log(f"[ida-mcp] discovery retry-timeout(ms): {IDA_DISCOVERY_RETRY_TIMEOUT_MS}")
    log(f"[ida-mcp] discovery cache file: {IDA_DISCOVERY_CACHE_FILE}")
    for warning in IDA_TARGET_WARNINGS:
        log(f"[ida-mcp] target config warning: {warning}")
    if IDA_AUTO_DISCOVER_ON_START:
        if _should_skip_startup_discovery(cache):
            log("[ida-mcp] startup discovery skipped by min interval")
        else:
            discovered = _discover_targets(
                host=IDA_DISCOVERY_HOST,
                port_start=IDA_DISCOVERY_PORT_START,
                port_end=IDA_DISCOVERY_PORT_END,
                timeout_ms=250,
                prune=True,
                max_duration_sec=IDA_STARTUP_DISCOVERY_TIMEOUT_SEC,
                stop_after_consecutive_misses=IDA_STARTUP_DISCOVERY_STOP_AFTER_MISSES,
            )
            if isinstance(discovered, dict) and "error" in discovered:
                log(f"[ida-mcp] startup discovery failed: {discovered['error']}")
            elif isinstance(discovered, dict):
                log(
                    "[ida-mcp] startup discovery done: "
                    f"found={len(discovered.get('discovered', []))}, "
                    f"removed={len(discovered.get('removed', []))}, "
                    f"total={discovered.get('total_targets')}, "
                    f"scanned_ports={discovered.get('scanned_ports')}, "
                    f"truncated={discovered.get('truncated')}, "
                    f"reason={discovered.get('break_reason')}"
                )
    while True:
        line = sys.stdin.readline()
        if not line:
            time.sleep(0.05)
            continue
        raw = line.rstrip("\n")
        log(f"[ida-mcp] <- MCP stdin raw: {raw}")

        try:
            req = json.loads(raw)
        except Exception:
            log("[ida-mcp] json parse error")
            continue

        method = req.get("method")
        req_id = req.get("id", None)

        # ignore notifications
        if method and method.startswith("notifications/"):
            log(f"[ida-mcp] ignore notification: {method}")
            continue

        try:
            if method == "initialize":
                handle_initialize(req)
            elif method == "tools/list":
                handle_tools_list(req)
            elif method == "tools/call":
                handle_tools_call(req)
            elif method == "resources/list":
                handle_resources_list(req)
            elif method == "resources/read":
                handle_resources_read(req)
            elif method == "resources/templates/list":
                handle_resources_templates_list(req)
            elif method == "ping":
                safe_send({"jsonrpc": "2.0", "id": req_id, "result": {}})
            else:
                # unknown method: only reply if it's a request (has id)
                log(f"[ida-mcp] unknown method: {method}")
                if req_id is not None:
                    safe_send({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method not found: {method}",
                        },
                    })
        except Exception:
            log("[ida-mcp] handler exception:\n" + traceback.format_exc())
            continue


if __name__ == "__main__":
    main()


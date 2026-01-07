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
def ida_request(method: str, **params):
    log(f"[ida-mcp] -> IDA request: {method} {params}")
    try:
        s = socket.create_connection((IDA_HOST, IDA_PORT), timeout=5.0)
    except OSError as e:
        err = {"error": f"connect ida failed: {e}"}
        log(f"[ida-mcp] <- IDA error(connect): {err}")
        return err
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
    s.close()
    if not data:
        err = {"error": "empty reply from ida"}
        log(f"[ida-mcp] <- IDA error(empty): {err}")
        return err
    text = data.decode("utf-8", "ignore").strip()
    log(f"[ida-mcp] <- IDA raw: {text}")
    try:
        return json.loads(text)
    except Exception as e:
        err = {"error": f"bad json from ida: {e}", "raw": text}
        log(f"[ida-mcp] <- IDA error(json): {err}")
        return err


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
                "version": "0.2.1",
            },
        },
    }
    safe_send(resp)


def handle_tools_list(req: dict):
    log("[ida-mcp] tools/list called")
    # 全部用英文描述，避免再出编码问题
    tools = [
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
            "name": "ida_add_pseudocode_comment",
            "description": "Add a comment inside Hex-Rays pseudocode at the given line number (line+comment plus name or ea required)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "ea": {"type": "integer"},
                        "line": {"type": "integer"},
                        "comment": {"type": "string"},
                        "repeatable": {"type": "boolean", "default": False},
                    },
                    "required": ["name","line", "comment"],
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
    ]
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
        if tool_name == "ida_list_functions":
            data = ida_request("list_functions")
            ok(json.dumps(data, ensure_ascii=True, indent=2))

        elif tool_name == "ida_call_graph":
            name = args.get("name")
            max_depth = int(args.get("max_depth", 2))
            data = ida_request("call_graph", root_name=name, max_depth=max_depth)
            ok(json.dumps(data, ensure_ascii=True, indent=2))

        elif tool_name == "ida_analyze_function":
            name = args.get("name")
            max_depth = int(args.get("max_depth", 2))
            rename = bool(args.get("rename", False))
            rename_locals = bool(args.get("rename_locals", False))

            analysis = ida_request("analyze_function", name=name, max_depth=max_depth)
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
                    ida_request("rename_function", ea=int(ea), new_name=new_name)
                    if rename_locals:
                        ida_request("rename_locals", ea=int(ea), names=["ctx", "arg", "tmp", "ret"])

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
            pseudo = ida_request("get_pseudocode", **pseudo_params)
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
            disasm = ida_request("get_disassembly", **disasm_params)
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

        elif tool_name == "ida_add_pseudocode_comment":
            name = args.get("name")
            ea_arg = args.get("ea")
            line = args.get("line")
            comment = args.get("comment")
            repeatable = bool(args.get("repeatable", False))
            if comment is None or line is None:
                err("line and comment required")
                return
            try:
                line_number = int(line)
            except Exception:
                err("line must be an integer")
                return
            comment_params = {
                "line": line_number,
                "comment": comment,
                "repeatable": repeatable,
            }
            if ea_arg is not None:
                try:
                    comment_params["ea"] = int(ea_arg)
                except Exception:
                    err("ea must be an integer")
                    return
            elif name:
                comment_params["name"] = name
            else:
                err("name or ea required")
                return
            resp = ida_request("add_pseudocode_comment", **comment_params)
            if "error" in resp:
                err("add comment failed: " + resp["error"])
                return
            ok(f"pseudocode line {line_number} annotated", meta=resp)

        elif tool_name == "ida_rename_function":
            old_name = args.get("old_name")
            new_name = args.get("new_name")
            funcs = ida_request("list_functions")
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
            ida_request("rename_function", ea=int(target_ea), new_name=new_name)
            ok(f"renamed {old_name} -> {new_name}")

        elif tool_name == "ida_get_imports":
            data = ida_request("get_imports")
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
            data = ida_request("get_exports")
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
            
            data = ida_request("get_xrefs_to", target=target)
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
            
            data = ida_request("list_globals", offset=offset, count=count)
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
            
            data = ida_request("read_memory_bytes", address=address, size=size)
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
            
            data = ida_request("get_strings", min_length=min_length, offset=offset, count=count)
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
            
            data = ida_request("jump_to_address", address=address)
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
            
            data = ida_request("set_data_type", address=address, data_type=data_type)
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
            
            data = ida_request("set_function_pointer_type", address=address, function_signature=function_signature)
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
            
            data = ida_request("set_name", address=address, name=name)
            if "error" in data:
                error_msg = data["error"]
                # 如果是地址未映射的错误，尝试先创建 segment
                if "is not mapped" in error_msg:
                    log(f"[ida-mcp] Address not mapped, attempting to create segment at {hex(address)}")
                    
                    # 创建 segment
                    segment_name = f"seg_{hex(address)[2:].upper()}"
                    create_result = ida_request("create_segment", address=address, name=segment_name, size=0x10000)
                    
                    if "error" not in create_result:
                        log(f"[ida-mcp] Successfully created segment, retrying set_name")
                        # 重新尝试设置名称
                        retry_data = ida_request("set_name", address=address, name=name)
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
            
            data = ida_request("create_function_pointer", address=address, name=name, function_signature=function_signature)
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

        else:
            err(f"unknown tool: {tool_name}")

    except Exception:
        err("exception:\n" + traceback.format_exc())


def _sanitize_resource_id(name: str) -> str:
    return re.sub(r"[^0-9a-zA-Z_-]+", "_", name)


def handle_resources_list(req: dict):
    log("[ida-mcp] resources/list called")
    funcs = ida_request("list_functions")
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
                pseudo = ida_request("get_pseudocode", name=name)
                
                if "error" in pseudo:
                    # If pseudocode fails, try disassembly
                    log(f"[ida-mcp] pseudocode failed, trying disassembly")
                    disasm = ida_request("get_disassembly", name=name)
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

# ida_bridge.py -- IDA 9.2 plugin, expose analysis over TCP for MCP
#
# 放到 IDA 的 plugins 目录
# 启动 IDA 后会自动开一个线程监听 127.0.0.1:31337
# MCP 服务器通过这个端口发 JSON 请求

import socket
import threading
import json
import traceback

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_bytes
import idautils
import ida_name
import idaapi
import ida_lines
import idc
import ida_nalt
import ida_entry

# 尝试 Hex-Rays
try:
    import ida_hexrays
    HAS_HEXRAYS = ida_hexrays.init_hexrays_plugin()
except Exception:
    HAS_HEXRAYS = False

HOST = "127.0.0.1"
PORT = 31337


# ---------- 工具函数 ----------

def _is_call(ea):
    try:
        return idaapi.is_call_insn(ea)
    except Exception:
        return False


def _list_functions():
    funcs = []
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        funcs.append({"ea": ea, "name": name})
    return funcs


def _build_callers_map():
    callers = {}
    for func_ea in idautils.Functions():
        f_name = ida_funcs.get_func_name(func_ea)
        for xref in idautils.XrefsTo(func_ea):
            caller = ida_funcs.get_func(xref.frm)
            if caller:
                callers.setdefault(f_name, set()).add(
                    ida_funcs.get_func_name(caller.start_ea)
                )
    return {k: list(v) for k, v in callers.items()}


def _build_call_graph(max_depth=2, root_name=None):
    """
    简单版调用图：基于指令层面发现 call，再按深度展开。
    用 _is_call(...) 来判断是否调用指令，兼容 9.2。
    """
    name_to_ea = {ida_funcs.get_func_name(ea): ea for ea in idautils.Functions()}
    if root_name and root_name not in name_to_ea:
        return {"error": f"function {root_name} not found"}

    def walk(ea, depth, seen):
        if depth > max_depth:
            return {}
        func = ida_funcs.get_func(ea)
        if not func:
            return {}
        this_name = ida_funcs.get_func_name(ea)
        if this_name in seen:
            return {}
        seen.add(this_name)
        callees = []

        for head in idautils.FuncItems(ea):
            if _is_call(head):
                # 找从这条 call 出去的引用
                for x in idautils.XrefsFrom(head, 0):
                    callee = ida_funcs.get_func(x.to)
                    if callee:
                        callee_name = ida_funcs.get_func_name(callee.start_ea)
                        callees.append(callee_name)

        node = {"name": this_name, "callees": []}
        for cname in callees:
            cea = name_to_ea.get(cname)
            if cea:
                child = walk(cea, depth + 1, seen)
                if child:
                    node["callees"].append(child)
                else:
                    node["callees"].append({"name": cname, "callees": []})
            else:
                node["callees"].append({"name": cname, "callees": []})
        return node

    if root_name:
        root_ea = name_to_ea[root_name]
        return walk(root_ea, 0, set())
    else:
        graph = {}
        for name, ea in name_to_ea.items():
            graph[name] = walk(ea, 0, set())
        return graph


def _guess_function_role(ea):
    """
    非常简单的启发式，后面你可以自己加规则
    """
    fn_name = ida_funcs.get_func_name(ea)
    callers_map = _build_callers_map()
    callers = callers_map.get(fn_name, [])
    role = []
    ln = fn_name.lower()
    if "init" in ln or "startup" in ln:
        role.append("init")
    elif len(callers) > 5:
        role.append("hotspot")
    else:
        role.append("normal")
    return {
        "name": fn_name,
        "ea": ea,
        "callers": callers,
        "role": role,
    }


def _find_function_ea(name):
    for f_ea in idautils.Functions():
        if ida_funcs.get_func_name(f_ea) == name:
            return f_ea
    return None


def _get_pseudocode(ea):
    if not HAS_HEXRAYS:
        return {"error": "Hex-Rays not available"}
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as exc:
        return {"error": f"decompile failed: {exc}"}
    if not cfunc:
        return {"error": "decompile returned no pseudocode"}
    pseudo = str(cfunc)
    return {
        "ea": ea,
        "name": ida_funcs.get_func_name(ea),
        "pseudocode": pseudo,
    }


def _set_pseudocode_comment(ea, line, comment, repeatable=False):
    if not HAS_HEXRAYS:
        return {"error": "Hex-Rays not available"}
    try:
        target_line = int(line)
    except Exception:
        return {"error": "line must be an integer"}
    if target_line <= 0:
        return {"error": "line must be positive"}
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as exc:
        return {"error": f"decompile failed: {exc}"}
    if not cfunc:
        return {"error": "decompile returned no pseudocode"}
    
    # Load existing user comments
    if hasattr(cfunc, "load_user_cmts"):
        try:
            cfunc.load_user_cmts()
        except Exception:
            pass
    
    # Find the tree location for the target line (1-based input)
    treeloc = None
    try:
        # Get pseudocode lines
        sv = cfunc.get_pseudocode()
        if not sv or target_line > len(sv):
            return {"error": f"line {target_line} out of range (function has {len(sv) if sv else 0} lines)"}
        
        # Get the pseudocode line (convert from 1-based to 0-based)
        pc_line = sv[target_line - 1]
        
        # Create treeloc from the pseudocode line's EA
        if hasattr(pc_line, 'ea') and pc_line.ea != idaapi.BADADDR:
            treeloc = ida_hexrays.treeloc_t()
            treeloc.ea = pc_line.ea
            treeloc.itp = ida_hexrays.ITP_SEMI
        else:
            # If no EA, try to find a nearby line with an EA
            for offset in range(1, min(5, len(sv) - target_line + 1)):
                check_line = target_line - 1 + offset
                if check_line < len(sv):
                    pc_line = sv[check_line]
                    if hasattr(pc_line, 'ea') and pc_line.ea != idaapi.BADADDR:
                        treeloc = ida_hexrays.treeloc_t()
                        treeloc.ea = pc_line.ea
                        treeloc.itp = ida_hexrays.ITP_SEMI
                        break
            
            # Try before the target line
            if not treeloc:
                for offset in range(1, min(5, target_line)):
                    check_line = target_line - 1 - offset
                    if check_line >= 0:
                        pc_line = sv[check_line]
                        if hasattr(pc_line, 'ea') and pc_line.ea != idaapi.BADADDR:
                            treeloc = ida_hexrays.treeloc_t()
                            treeloc.ea = pc_line.ea
                            treeloc.itp = ida_hexrays.ITP_SEMI
                            break
    except Exception as exc:
        return {"error": f"failed to find tree location: {exc}"}
    
    if not treeloc:
        return {"error": f"could not find tree location for line {target_line}"}
    
    # Set the comment using treeloc_t
    try:
        cfunc.set_user_cmt(treeloc, comment)
    except Exception as exc:
        return {"error": f"failed to set comment: {exc}"}
    
    # Save user comments
    try:
        cfunc.save_user_cmts()
    except Exception:
        pass
    
    # Refresh the view
    if hasattr(ida_hexrays, "refresh_hexrays_view"):
        try:
            ida_hexrays.refresh_hexrays_view()
        except Exception:
            pass
    
    return {
        "ea": ea,
        "line": target_line,
        "comment": comment,
        "ok": True,
    }


def _get_disassembly(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return {"error": "function not found"}
    lines = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        disasm = idc.generate_disasm_line(head, 0)
        if isinstance(disasm, tuple):
            line_text = disasm[0]
        else:
            line_text = disasm
        line_text = ida_lines.tag_remove(line_text)
        lines.append(f"{hex(head)}: {line_text}")
    return {
        "ea": ea,
        "name": ida_funcs.get_func_name(ea),
        "disassembly": "\n".join(lines),
    }


def _rename_function(ea, new_name):
    ida_name.set_name(ea, new_name, ida_name.SN_AUTO)


def _rename_locals(ea, names):
    if not HAS_HEXRAYS:
        return {"ok": False, "reason": "Hex-Rays not available"}
    try:
        cfunc = ida_hexrays.decompile(ea)
    except Exception as e:
        return {"ok": False, "reason": f"decompile failed: {e}"}
    lvars = cfunc.get_lvars()
    for i, lv in enumerate(lvars):
        if i < len(names):
            cfunc.set_lvar_name(lv, names[i])
    cfunc.save_user_cmts()
    return {"ok": True}


def _get_imports():
    """
    获取导入表信息
    """
    imports = []
    nimps = ida_nalt.get_import_module_qty()
    
    for i in range(nimps):
        dllname = ida_nalt.get_import_module_name(i)
        if not dllname:
            continue
            
        def imp_cb(ea, name, ordinal):
            if name:
                imports.append({
                    "ea": ea,
                    "name": name,
                    "ordinal": ordinal,
                    "module": dllname
                })
            return True
        
        ida_nalt.enum_import_names(i, imp_cb)
    
    return imports


def _get_exports():
    """
    获取导出表信息
    """
    exports = []
    
    for idx in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(idx)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        
        exports.append({
            "ordinal": ordinal,
            "ea": ea,
            "name": name if name else f"ord_{ordinal}"
        })
    
    return exports


def _get_xrefs_to(target):
    """
    获取对某个地址或名称的所有引用
    target 可以是地址(int)或名称(str)
    """
    if isinstance(target, str):
        # 通过名称查找地址
        ea = ida_name.get_name_ea(idaapi.BADADDR, target)
        if ea == idaapi.BADADDR:
            # 尝试在所有段中搜索名称
            found = False
            for segea in idautils.Segments():
                seg = idaapi.getseg(segea)
                if seg:
                    for head in idautils.Heads(seg.start_ea, seg.end_ea):
                        name = ida_name.get_name(head)
                        if name and (name == target or name.startswith(target + "@@")):
                            ea = head
                            found = True
                            break
                    if found:
                        break
            
            if not found:
                return {"error": f"name '{target}' not found"}
    else:
        try:
            ea = int(target)
        except Exception:
            return {"error": "target must be an integer address or string name"}
    
    # 获取目标名称
    target_name = ida_name.get_name(ea) if isinstance(target, int) else target
    
    xrefs = []
    for xref in idautils.XrefsTo(ea):
        # 获取引用类型描述 (IDA 9.2 兼容)
        xref_type_map = {
            0: "Data_Unknown",
            1: "Data_Offset", 
            2: "Data_Write",
            3: "Data_Read",
            4: "Data_Text",
            5: "Data_Informational",
            16: "Code_Far_Call",
            17: "Code_Near_Call",
            18: "Code_Far_Jump",
            19: "Code_Near_Jump",
            20: "Code_User",
            21: "Ordinary_Flow"
        }
        xref_type = xref_type_map.get(xref.type, f"Unknown_{xref.type}")
        
        func = ida_funcs.get_func(xref.frm)
        func_name = ida_funcs.get_func_name(func.start_ea) if func else "<no_func>"
        
        # 获取引用处的反汇编
        disasm = idc.generate_disasm_line(xref.frm, 0)
        if isinstance(disasm, tuple):
            disasm_text = disasm[0]
        else:
            disasm_text = disasm
        disasm_text = ida_lines.tag_remove(disasm_text)
        
        xrefs.append({
            "from_ea": xref.frm,
            "to_ea": xref.to,
            "type": xref_type,
            "function": func_name,
            "disasm": disasm_text
        })
    
    return {
        "target": target,
        "target_name": target_name,
        "target_ea": ea,
        "xrefs": xrefs,
        "count": len(xrefs)
    }


def _list_globals(offset=0, count=100):
    """
    列出所有全局变量/数据(分页)
    """
    try:
        offset = int(offset)
        count = int(count)
    except Exception:
        return {"error": "offset and count must be integers"}
    
    if offset < 0:
        offset = 0
    if count <= 0 or count > 1000:
        count = 100
    
    globals_list = []
    
    # 遍历所有命名的地址
    all_names = []
    for segea in idautils.Segments():
        seg = idaapi.getseg(segea)
        if not seg:
            continue
        
        # 只处理数据段
        if seg.type == idaapi.SEG_DATA or seg.type == idaapi.SEG_BSS:
            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                name = ida_name.get_name(head)
                if name:
                    # 过滤掉函数
                    if not ida_funcs.get_func(head):
                        # 获取数据类型和大小
                        flags = ida_bytes.get_flags(head)
                        size = ida_bytes.get_item_size(head)
                        
                        # 判断数据类型
                        if ida_bytes.is_byte(flags):
                            dtype = "byte"
                        elif ida_bytes.is_word(flags):
                            dtype = "word"
                        elif ida_bytes.is_dword(flags):
                            dtype = "dword"
                        elif ida_bytes.is_qword(flags):
                            dtype = "qword"
                        elif ida_bytes.is_strlit(flags):
                            dtype = "string"
                        else:
                            dtype = "unknown"
                        
                        all_names.append({
                            "ea": head,
                            "name": name,
                            "type": dtype,
                            "size": size,
                            "segment": idc.get_segm_name(head)
                        })
    
    # 分页
    total = len(all_names)
    paginated = all_names[offset:offset + count]
    
    return {
        "globals": paginated,
        "total": total,
        "offset": offset,
        "count": len(paginated),
        "has_more": offset + count < total
    }


def _read_memory_bytes(address, size):
    """
    读取指定地址的字节
    """
    try:
        ea = int(address)
        size = int(size)
    except Exception:
        return {"error": "address and size must be integers"}
    
    if size <= 0 or size > 65536:
        return {"error": "size must be between 1 and 65536"}
    
    # 检查地址是否有效
    if not idaapi.is_mapped(ea):
        return {"error": f"address {hex(ea)} is not mapped"}
    
    # 读取字节
    data = ida_bytes.get_bytes(ea, size)
    if data is None:
        return {"error": f"failed to read {size} bytes at {hex(ea)}"}
    
    # 转换为十六进制字符串和字节列表
    hex_str = data.hex()
    byte_list = list(data)
    
    # 尝试获取地址名称
    name = ida_name.get_name(ea)
    
    return {
        "address": ea,
        "size": len(data),
        "name": name if name else None,
        "hex": hex_str,
        "bytes": byte_list,
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    }


def _get_strings(min_length=4, offset=0, count=100):
    """
    获取程序中的所有字符串(分页)
    """
    try:
        min_length = int(min_length)
        offset = int(offset)
        count = int(count)
    except Exception:
        return {"error": "min_length, offset and count must be integers"}
    
    if min_length < 1:
        min_length = 4
    if offset < 0:
        offset = 0
    if count <= 0 or count > 1000:
        count = 100
    
    strings = []
    
    # 遍历所有字符串
    sc = idautils.Strings()
    sc.setup(minlen=min_length)
    
    all_strings = []
    for s in sc:
        try:
            # 获取字符串地址和内容
            ea = s.ea
            length = s.length
            strtype = s.strtype
            
            # 读取字符串内容
            content = idc.get_strlit_contents(ea, length, strtype)
            if content:
                # 转换为可读字符串
                if isinstance(content, bytes):
                    try:
                        text = content.decode('utf-8', errors='ignore')
                    except Exception:
                        text = str(content)
                else:
                    text = str(content)
                
                # 获取字符串类型描述
                strtype_map = {
                    0: "C",           # STRTYPE_C
                    1: "C_16",        # STRTYPE_C_16
                    2: "C_32",        # STRTYPE_C_32
                    32: "Pascal",     # STRTYPE_PASCAL
                    33: "Pascal_16",  # STRTYPE_PASCAL_16
                }
                type_name = strtype_map.get(strtype, f"Type_{strtype}")
                
                # 获取引用该字符串的位置
                xrefs = []
                for xref in idautils.XrefsTo(ea):
                    func = ida_funcs.get_func(xref.frm)
                    func_name = ida_funcs.get_func_name(func.start_ea) if func else "<no_func>"
                    xrefs.append({
                        "from": xref.frm,
                        "function": func_name
                    })
                
                all_strings.append({
                    "ea": ea,
                    "length": length,
                    "type": type_name,
                    "content": text,
                    "xrefs_count": len(xrefs),
                    "xrefs": xrefs[:5]  # 只保留前5个引用
                })
        except Exception:
            continue
    
    # 分页
    total = len(all_strings)
    paginated = all_strings[offset:offset + count]
    
    return {
        "strings": paginated,
        "total": total,
        "offset": offset,
        "count": len(paginated),
        "has_more": offset + count < total
    }


def handle_one_request(req: dict):
    method = req.get("method")
    params = req.get("params", {}) or {}
    if method == "list_functions":
        return _list_functions()
    elif method == "call_graph":
        return _build_call_graph(
            max_depth=int(params.get("max_depth", 2)),
            root_name=params.get("root_name"),
        )
    elif method == "analyze_function":
        name = params.get("name")
        if not name:
            return {"error": "name required"}
        target_ea = _find_function_ea(name)
        if target_ea is None:
            return {"error": f"function {name} not found"}
        info = _guess_function_role(target_ea)
        info["call_tree"] = _build_call_graph(
            max_depth=int(params.get("max_depth", 2)),
            root_name=name,
        )
        return info
    elif method == "rename_function":
        ea = int(params["ea"])
        new_name = params["new_name"]
        _rename_function(ea, new_name)
        return {"ok": True}
    elif method == "rename_locals":
        ea = int(params["ea"])
        names = params.get("names", [])
        return _rename_locals(ea, names)
    elif method == "get_pseudocode":
        raw_ea = params.get("ea")
        target_name = params.get("name")
        if raw_ea is None:
            if not target_name:
                return {"error": "name or ea required"}
            target_ea = _find_function_ea(target_name)
            if target_ea is None:
                return {"error": f"function {target_name} not found"}
        else:
            try:
                target_ea = int(raw_ea)
            except Exception:
                return {"error": "ea must be an integer"}
        return _get_pseudocode(target_ea)
    elif method == "add_pseudocode_comment":
        comment = params.get("comment")
        line = params.get("line")
        if comment is None or line is None:
            return {"error": "comment and line required"}
        raw_ea = params.get("ea")
        target_name = params.get("name")
        if raw_ea is None:
            if not target_name:
                return {"error": "name or ea required"}
            target_ea = _find_function_ea(target_name)
            if target_ea is None:
                return {"error": f"function {target_name} not found"}
        else:
            try:
                target_ea = int(raw_ea)
            except Exception:
                return {"error": "ea must be an integer"}
        repeatable = bool(params.get("repeatable", False))
        return _set_pseudocode_comment(target_ea, line, comment, repeatable)
    elif method == "get_disassembly":
        raw_ea = params.get("ea")
        target_name = params.get("name")
        if raw_ea is None:
            if not target_name:
                return {"error": "name or ea required"}
            target_ea = _find_function_ea(target_name)
            if target_ea is None:
                return {"error": f"function {target_name} not found"}
        else:
            try:
                target_ea = int(raw_ea)
            except Exception:
                return {"error": "ea must be an integer"}
        return _get_disassembly(target_ea)
    elif method == "get_imports":
        return {"imports": _get_imports()}
    elif method == "get_exports":
        return {"exports": _get_exports()}
    elif method == "get_xrefs_to":
        target = params.get("target")
        if target is None:
            return {"error": "target required (address or name)"}
        return _get_xrefs_to(target)
    elif method == "list_globals":
        offset = int(params.get("offset", 0))
        count = int(params.get("count", 100))
        return _list_globals(offset, count)
    elif method == "read_memory_bytes":
        address = params.get("address")
        size = params.get("size")
        if address is None or size is None:
            return {"error": "address and size required"}
        return _read_memory_bytes(address, size)
    elif method == "get_strings":
        min_length = int(params.get("min_length", 4))
        offset = int(params.get("offset", 0))
        count = int(params.get("count", 100))
        return _get_strings(min_length, offset, count)
    else:
        return {"error": f"unknown method {method}"}


def serve():
    global PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, PORT))
    except OSError:
        PORT += 1
        sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"[ida-bridge] listening on {HOST}:{PORT}")

    while True:
        conn, addr = sock.accept()
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk:
                break
        try:
            req = json.loads(data.decode("utf-8").strip())

            def _do():
                try:
                    res = handle_one_request(req)
                except Exception:
                    res = {"error": traceback.format_exc()}
                conn.sendall((json.dumps(res) + "\n").encode("utf-8"))
                conn.close()

            ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST)
        except Exception:
            traceback.print_exc()
            conn.close()


class ida_bridge_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "IDA bridge for MCP"
    help = "Expose IDA analysis via TCP for external MCP server"
    wanted_name = "ida_bridge"
    wanted_hotkey = ""

    def init(self):
        # 防止多次起线程
        if getattr(ida_idaapi, "_IDA_BRIDGE_STARTED", False):
            print("[ida-bridge] already started, skip")
            return ida_idaapi.PLUGIN_KEEP
        ida_idaapi._IDA_BRIDGE_STARTED = True

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        print("[ida-bridge] server thread started")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return ida_bridge_plugin_t()

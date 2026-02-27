# ida_bridge.py -- IDA 9.2 plugin, expose analysis over TCP for MCP
#
# 放到 IDA 的 plugins 目录
# 启动 IDA 后会自动开一个线程监听 127.0.0.1:31337
# MCP 服务器通过这个端口发 JSON 请求

import socket
import threading
import json
import traceback
import os
import time

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
BRIDGE_STARTED_AT = int(time.time())


# ---------- 工具函数 ----------

def _normalize_function_signature(signature):
    """
    规范化函数签名，处理常见的格式问题
    """
    sig = signature.strip()
    
    # 常见的函数签名模板
    templates = {
        # Windows API 常见类型
        "NTSTATUS": "NTSTATUS (*func)(void*, void*, int, int, int);",
        "HANDLE": "HANDLE (*func)(void*, void*, int, int, int);",
        "BOOL": "BOOL (*func)(void*, void*, int, int, int);", 
        "DWORD": "DWORD (*func)(void*, void*, int, int, int);",
        "PVOID": "PVOID (*func)(void*, void*, int, int, int);",
        
        # 通用类型
        "int": "int (*func)(void*, void*, int, int, int);",
        "void": "void (*func)(void*, void*, int, int, int);",
        "void*": "void* (*func)(void*, void*, int, int, int);",
        "long": "long (*func)(void*, void*, int, int, int);",
        "uint64_t": "uint64_t (*func)(void*, void*, int, int, int);",
    }
    
    # 如果是简单的类型名，使用模板
    if sig in templates:
        return templates[sig]
    
    # 如果已经是完整的函数指针声明，直接返回
    if "(*" in sig or "(__" in sig:
        # 确保以分号结尾
        if not sig.endswith(';'):
            sig += ';'
        return sig
    
    # 尝试解析为返回类型 + 调用约定的形式
    # 例如: "NTSTATUS __fastcall" -> "NTSTATUS (__fastcall *func)(...)"
    parts = sig.split()
    if len(parts) >= 2:
        return_type = parts[0]
        calling_conv = parts[1]
        return f"{return_type} ({calling_conv} *func)(void*, void*, int, int, int);"
    
    # 默认情况：假设是返回类型
    return f"{sig} (*func)(void*, void*, int, int, int);"


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


def _get_instance_info():
    """
    返回当前 IDA 实例信息，供 MCP 侧主动发现与标识
    """
    try:
        idb_path = idc.get_idb_path() or ""
    except Exception:
        idb_path = ""

    try:
        input_file = idc.get_input_file_path() or ""
    except Exception:
        input_file = ""

    try:
        input_file_name = ida_nalt.get_root_filename() or ""
    except Exception:
        input_file_name = ""

    try:
        imagebase = idaapi.get_imagebase()
    except Exception:
        imagebase = None

    try:
        is_64bit = bool(idaapi.inf_is_64bit())
    except Exception:
        is_64bit = None

    try:
        functions_count = int(ida_funcs.get_func_qty())
    except Exception:
        try:
            functions_count = len(list(idautils.Functions()))
        except Exception:
            functions_count = None

    return {
        "ok": True,
        "bridge": "ida_bridge",
        "bridge_version": "0.4.0",
        "pid": os.getpid(),
        "port": PORT,
        "started_at": BRIDGE_STARTED_AT,
        "database_path": idb_path,
        "database_name": os.path.basename(idb_path) if idb_path else "",
        "idb_name": os.path.basename(idb_path) if idb_path else "",
        "input_file": input_file,
        "input_file_name": input_file_name,
        "imagebase": imagebase,
        "is_64bit": is_64bit,
        "functions_count": functions_count,
    }


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


def _py_exec(code):
    r"""
    Execute Python code in IDA's Python interpreter
    Returns result, output, and any error messages
    
    Encoding Note for Comments with Unicode/Chinese Characters:
    - The 'code' parameter is received as a UTF-8 decoded string from JSON
    - Non-ASCII characters (e.g., Chinese) are transmitted as \uXXXX escape sequences
      in JSON (via ensure_ascii=True in mcp_ida_server.py)
    - Python's compile() and exec() correctly handle Unicode string literals
    - This ensures idc.set_func_cmt() and cfunc.set_user_cmt() receive proper Unicode
      strings for comments with Chinese/non-ASCII characters
    - Example: cfunc.set_user_cmt(tl, '初始化') works because '初始化' is properly
      decoded from JSON's \u521d\u59cb\u5316 escape sequence
    
    Critical: Do NOT manually encode/decode the 'code' parameter - it's already UTF-8
    decoded. Simply compile and execute it as-is.
    """
    import sys
    from io import StringIO
    
    # Capture stdout/stderr
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    captured_output = StringIO()
    captured_error = StringIO()
    
    sys.stdout = captured_output
    sys.stderr = captured_error
    
    result = None
    error_msg = None
    
    try:
        # Try to compile and execute the code
        compiled_code = compile(code, "<py_exec>", "exec")
        
        # Create a namespace with common IDA modules
        namespace = {
            "idaapi": idaapi,
            "idc": idc,
            "idautils": idautils,
            "ida_funcs": ida_funcs,
            "ida_bytes": ida_bytes,
            "ida_name": ida_name,
            "ida_kernwin": ida_kernwin,
            "ida_lines": ida_lines,
            "ida_nalt": ida_nalt,
            "ida_entry": ida_entry,
        }
        
        # Add Hex-Rays if available
        if HAS_HEXRAYS:
            namespace["ida_hexrays"] = ida_hexrays
        
        # Try eval first (for expressions), then exec (for statements)
        try:
            # Try to compile as eval (expression)
            compiled_eval = compile(code, "<py_exec>", "eval")
            result = eval(compiled_eval, namespace)
        except SyntaxError:
            # Not an expression, use exec for statements
            exec(compiled_code, namespace)
            result = None
            
    except Exception as e:
        error_msg = traceback.format_exc()
    finally:
        # Restore stdout/stderr
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    
    output = captured_output.getvalue()
    error = captured_error.getvalue()
    
    if error:
        error_msg = (error_msg or "") + "\n" + error
    
    return {
        "result": result,
        "output": output,
        "error_msg": error_msg,
        "ok": error_msg is None
    }


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


def _jump_to_address(address):
    """
    跳转到指定地址（类似按 g 键）
    """
    try:
        ea = int(address)
    except Exception:
        return {"error": "address must be an integer"}
    
    # 检查地址是否有效
    if not idaapi.is_mapped(ea):
        return {"error": f"address {hex(ea)} is not mapped"}
    
    # 跳转到地址
    idaapi.jumpto(ea)
    
    return {
        "address": ea,
        "hex_address": hex(ea),
        "ok": True
    }


def _set_data_type(address, data_type):
    """
    设置指定地址的数据类型
    """
    try:
        ea = int(address)
    except Exception:
        return {"error": "address must be an integer"}
    
    if not idaapi.is_mapped(ea):
        return {"error": f"address {hex(ea)} is not mapped"}
    
    # 先删除现有数据
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE)
    
    # 根据类型设置数据
    success = False
    if data_type == "byte":
        success = ida_bytes.create_data(ea, ida_bytes.FF_BYTE, 1, idaapi.BADADDR)
    elif data_type == "word":
        success = ida_bytes.create_data(ea, ida_bytes.FF_WORD, 2, idaapi.BADADDR)
    elif data_type == "dword":
        success = ida_bytes.create_data(ea, ida_bytes.FF_DWORD, 4, idaapi.BADADDR)
    elif data_type == "qword":
        success = ida_bytes.create_data(ea, ida_bytes.FF_QWORD, 8, idaapi.BADADDR)
    elif data_type == "float":
        success = ida_bytes.create_data(ea, ida_bytes.FF_FLOAT, 4, idaapi.BADADDR)
    elif data_type == "double":
        success = ida_bytes.create_data(ea, ida_bytes.FF_DOUBLE, 8, idaapi.BADADDR)
    elif data_type == "ascii":
        success = ida_bytes.create_strlit(ea, 0, ida_nalt.STRTYPE_C)
    elif data_type == "unicode":
        success = ida_bytes.create_strlit(ea, 0, ida_nalt.STRTYPE_C_16)
    else:
        return {"error": f"unsupported data type: {data_type}"}
    
    if not success:
        return {"error": f"failed to set data type {data_type} at {hex(ea)}"}
    
    return {
        "address": ea,
        "hex_address": hex(ea),
        "data_type": data_type,
        "ok": True
    }


def _set_function_pointer_type(address, function_signature):
    """
    设置函数指针类型（类似按 Y 键）
    """
    try:
        ea = int(address)
    except Exception:
        return {"error": "address must be an integer"}
    
    if not idaapi.is_mapped(ea):
        return {"error": f"address {hex(ea)} is not mapped"}
    
    # 先设置为 QWORD 类型（函数指针通常是 8 字节）
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE)
    if not ida_bytes.create_data(ea, ida_bytes.FF_QWORD, 8, idaapi.BADADDR):
        return {"error": f"failed to set qword data at {hex(ea)}"}
    
    # 设置类型信息
    try:
        tinfo = idaapi.tinfo_t()
        
        # 规范化函数签名
        sig = _normalize_function_signature(function_signature)
        if not sig:
            return {"error": "empty function signature"}
        
        # 尝试解析类型 - 使用正确的参数
        til = idaapi.get_idati()
        if idaapi.parse_decl(tinfo, til, sig, idaapi.PT_TYP | idaapi.PT_SIL):
            # 成功解析，设置类型信息
            if ida_nalt.set_tinfo(ea, tinfo):
                return {
                    "address": ea,
                    "hex_address": hex(ea),
                    "function_signature": function_signature,
                    "parsed_signature": sig,
                    "ok": True
                }
            else:
                return {"error": f"failed to set type info at {hex(ea)}"}
        else:
            # 解析失败，尝试一些通用的函数指针类型
            generic_sigs = [
                "void* (*func)();",
                "int (*func)();",
                "void (*func)();",
                "NTSTATUS (*func)();"
            ]
            
            for generic_sig in generic_sigs:
                if idaapi.parse_decl(tinfo, til, generic_sig, idaapi.PT_TYP | idaapi.PT_SIL):
                    if ida_nalt.set_tinfo(ea, tinfo):
                        return {
                            "address": ea,
                            "hex_address": hex(ea),
                            "function_signature": function_signature,
                            "fallback_signature": generic_sig,
                            "warning": f"Original signature failed, used fallback: {generic_sig}",
                            "ok": True
                        }
            
            return {"error": f"failed to parse function signature: {function_signature}"}
        
    except Exception as e:
        return {"error": f"failed to set function pointer type: {e}"}


def _create_segment(address, size=0x1000, name="created_seg", seg_class="DATA"):
    """
    创建一个新的 segment
    """
    try:
        ea = int(address)
        size = int(size)
    except Exception:
        return {"error": "address and size must be integers"}
    
    # 页对齐起始地址
    aligned_start = ea & ~0xFFF
    # 计算结束地址，确保包含目标地址
    end_ea = max(aligned_start + size, ea + 0x100)
    # 页对齐结束地址
    aligned_end = (end_ea + 0xFFF) & ~0xFFF
    
    try:
        # 创建 segment
        seg = idaapi.segment_t()
        seg.start_ea = aligned_start
        seg.end_ea = aligned_end
        seg.bitness = 1  # 64-bit
        seg.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE
        
        # 设置 segment 类型
        if seg_class.upper() == "CODE":
            seg.type = idaapi.SEG_CODE
            seg.perm |= idaapi.SEGPERM_EXEC
        else:
            seg.type = idaapi.SEG_DATA
        
        # 添加 segment
        if idaapi.add_segm_ex(seg, name, seg_class, idaapi.ADDSEG_SPARSE):
            return {
                "address": ea,
                "hex_address": hex(ea),
                "segment_start": aligned_start,
                "segment_end": aligned_end,
                "segment_name": name,
                "ok": True
            }
        else:
            return {"error": f"failed to create segment at {hex(aligned_start)}"}
    except Exception as e:
        return {"error": f"failed to create segment: {e}"}


def _set_name(address, name):
    """
    设置地址的名字（类似按 N 键）
    智能处理：如果地址处存储的是函数指针，自动设置为 QWORD 并应用函数指针类型
    如果函数指针指向的目标地址无效，先为目标地址创建 segment
    """
    try:
        ea = int(address)
    except Exception:
        return {"error": "address must be an integer"}
    
    if not idaapi.is_mapped(ea):
        return {"error": f"address {hex(ea)} is not mapped"}
    
    results = {}
    
    # 读取地址处的值，检查是否是函数指针
    try:
        # 尝试读取 8 字节（64位指针）
        ptr_value = ida_bytes.get_qword(ea)
        if ptr_value and ptr_value != idaapi.BADADDR:
            results["pointer_value"] = hex(ptr_value)
            
            # 检查目标地址是否已映射
            target_mapped = idaapi.is_mapped(ptr_value)
            if not target_mapped:
                # 目标地址未映射，尝试创建 segment
                results["target_not_mapped"] = f"target address {hex(ptr_value)} not mapped"
                
                segment_name = f"seg_{hex(ptr_value)[2:].upper()}"
                seg_result = _create_segment(ptr_value, size=0x10000, name=segment_name, seg_class="CODE")
                
                if "error" not in seg_result:
                    results["segment_created"] = {
                        "name": segment_name,
                        "start": hex(seg_result.get("segment_start", 0)),
                        "end": hex(seg_result.get("segment_end", 0))
                    }
                    # 重新检查是否映射成功
                    target_mapped = idaapi.is_mapped(ptr_value)
                else:
                    results["segment_creation_failed"] = seg_result["error"]
            
            # 检查该值是否指向一个函数（或在新创建的 segment 中）
            target_func = ida_funcs.get_func(ptr_value)
            if target_func:
                results["detected"] = f"function pointer to {hex(ptr_value)}"
                results["target_function"] = ida_funcs.get_func_name(target_func.start_ea)
            elif target_mapped:
                # 即使不是函数，但目标地址已映射，也当作函数指针处理
                results["detected"] = f"pointer to {hex(ptr_value)} (may be function)"
                
            # 如果检测到指针（不管目标是否是函数），都进行处理
            if "detected" in results or target_mapped:
                # 1. 设置为 QWORD 数据类型
                try:
                    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE)
                    if ida_bytes.create_data(ea, ida_bytes.FF_QWORD, 8, idaapi.BADADDR):
                        results["data_type"] = "qword"
                    else:
                        results["data_type"] = "failed to set qword"
                except Exception as e:
                    results["data_type"] = f"error: {e}"
                
                # 2. 尝试设置函数指针类型（使用通用签名）
                try:
                    tinfo = idaapi.tinfo_t()
                    til = idaapi.get_idati()
                    
                    # 尝试多种通用函数指针类型
                    generic_sigs = [
                        "void* (*func)();",
                        "NTSTATUS (*func)();",
                        "int (*func)();",
                        "long (*func)();",
                    ]
                    
                    type_set = False
                    for sig in generic_sigs:
                        if idaapi.parse_decl(tinfo, til, sig, idaapi.PT_TYP | idaapi.PT_SIL):
                            if ida_nalt.set_tinfo(ea, tinfo):
                                results["function_type"] = sig
                                type_set = True
                                break
                    
                    if not type_set:
                        results["function_type"] = "failed to set"
                except Exception as e:
                    results["function_type"] = f"error: {e}"
                
                # 3. 刷新视图
                try:
                    ida_kernwin.refresh_idaview_anyway()
                    if HAS_HEXRAYS:
                        ida_hexrays.refresh_hexrays_view()
                except Exception:
                    pass
            else:
                results["detected"] = f"not a function pointer (points to {hex(ptr_value)})"
    except Exception as e:
        results["detection_error"] = str(e)
    
    # 设置名字 - 处理名称冲突
    final_name = name
    name_set = False
    
    # 首先检查名称是否已存在
    existing_ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if existing_ea != idaapi.BADADDR and existing_ea != ea:
        # 名称已被使用在其他地址
        results["name_conflict"] = f"name '{name}' already used at {hex(existing_ea)}"
        
        # 尝试使用带后缀的名称
        for i in range(1, 100):
            candidate_name = f"{name}_{i}"
            test_ea = ida_name.get_name_ea(idaapi.BADADDR, candidate_name)
            if test_ea == idaapi.BADADDR or test_ea == ea:
                # 这个名称可用
                if ida_name.set_name(ea, candidate_name, ida_name.SN_AUTO):
                    final_name = candidate_name
                    name_set = True
                    results["name_resolution"] = f"used alternate name: {candidate_name}"
                    break
        
        if not name_set:
            # 如果所有后缀都失败，尝试使用 SN_NOWARN 强制设置
            if ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_AUTO):
                name_set = True
                results["name_resolution"] = "forced name with SN_NOWARN"
            else:
                return {
                    "error": f"failed to set name '{name}' at {hex(ea)} - name already used at {hex(existing_ea)}",
                    "existing_address": hex(existing_ea),
                    "auto_processing": results
                }
    else:
        # 名称未被使用或已经是当前地址的名称
        if ida_name.set_name(ea, name, ida_name.SN_AUTO):
            name_set = True
        else:
            # 尝试使用 SN_NOWARN
            if ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_AUTO):
                name_set = True
                results["name_resolution"] = "set with SN_NOWARN"
            else:
                return {"error": f"failed to set name '{name}' at {hex(ea)}"}
    
    return {
        "address": ea,
        "hex_address": hex(ea),
        "name": final_name,
        "auto_processing": results if results else "none (not a function pointer)",
        "ok": True
    }


def _create_function_pointer(address, name, function_signature):
    """
    完整的函数指针创建流程：跳转、设置 QWORD、设置类型、命名
    """
    try:
        ea = int(address)
    except Exception:
        return {"error": "address must be an integer"}
    
    if not idaapi.is_mapped(ea):
        return {"error": f"address {hex(ea)} is not mapped"}
    
    results = {}
    
    # 1. 跳转到地址
    try:
        idaapi.jumpto(ea)
        results["jump"] = True
    except Exception as e:
        results["jump"] = f"failed: {e}"
    
    # 2. 设置为 QWORD 数据类型
    try:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE)
        if ida_bytes.create_data(ea, ida_bytes.FF_QWORD, 8, idaapi.BADADDR):
            results["data_type"] = "qword set successfully"
        else:
            results["data_type"] = "failed to set qword"
    except Exception as e:
        results["data_type"] = f"failed: {e}"
    
    # 3. 设置函数指针类型
    try:
        tinfo = idaapi.tinfo_t()
        til = idaapi.get_idati()
        
        # 规范化函数签名
        sig = _normalize_function_signature(function_signature)
        
        if idaapi.parse_decl(tinfo, til, sig, idaapi.PT_TYP | idaapi.PT_SIL):
            if ida_nalt.set_tinfo(ea, tinfo):
                results["function_type"] = f"set successfully: {sig}"
            else:
                results["function_type"] = "parsed but failed to set"
        else:
            # 尝试通用类型
            generic_sigs = [
                "void* (*func)();",
                "int (*func)();", 
                "void (*func)();",
                "NTSTATUS (*func)();"
            ]
            
            success = False
            for generic_sig in generic_sigs:
                if idaapi.parse_decl(tinfo, til, generic_sig, idaapi.PT_TYP | idaapi.PT_SIL):
                    if ida_nalt.set_tinfo(ea, tinfo):
                        results["function_type"] = f"set generic type: {generic_sig} (original failed: {function_signature})"
                        success = True
                        break
            
            if not success:
                results["function_type"] = f"failed to parse: {function_signature}"
    except Exception as e:
        results["function_type"] = f"failed: {e}"
    
    # 4. 设置名字
    try:
        if ida_name.set_name(ea, name, ida_name.SN_AUTO):
            results["name"] = f"set to '{name}'"
        else:
            results["name"] = f"failed to set '{name}'"
    except Exception as e:
        results["name"] = f"failed: {e}"
    
    # 刷新显示
    try:
        # 刷新 IDA 视图
        ida_kernwin.refresh_idaview_anyway()
        
        # 如果有 Hex-Rays，也刷新反编译视图
        if HAS_HEXRAYS:
            try:
                ida_hexrays.refresh_hexrays_view()
            except Exception:
                pass  # 忽略 Hex-Rays 刷新失败
        
        results["refresh"] = "views refreshed"
    except Exception as e:
        results["refresh"] = f"refresh failed: {e}"
    
    return {
        "address": ea,
        "hex_address": hex(ea),
        "name": name,
        "function_signature": function_signature,
        "results": results,
        "ok": True
    }


def handle_one_request(req: dict):
    method = req.get("method")
    params = req.get("params", {}) or {}
    if method == "ping":
        return {
            "ok": True,
            "bridge": "ida_bridge",
            "bridge_version": "0.4.0",
            "pid": os.getpid(),
            "port": PORT,
            "started_at": BRIDGE_STARTED_AT,
        }
    elif method == "get_instance_info":
        return _get_instance_info()
    elif method == "list_functions":
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
    elif method == "jump_to_address":
        address = params.get("address")
        if address is None:
            return {"error": "address required"}
        return _jump_to_address(address)
    elif method == "set_data_type":
        address = params.get("address")
        data_type = params.get("data_type")
        if address is None or data_type is None:
            return {"error": "address and data_type required"}
        return _set_data_type(address, data_type)
    elif method == "set_function_pointer_type":
        address = params.get("address")
        function_signature = params.get("function_signature")
        if address is None or function_signature is None:
            return {"error": "address and function_signature required"}
        return _set_function_pointer_type(address, function_signature)
    elif method == "set_name":
        address = params.get("address")
        name = params.get("name")
        if address is None or name is None:
            return {"error": "address and name required"}
        return _set_name(address, name)
    elif method == "create_function_pointer":
        address = params.get("address")
        name = params.get("name")
        function_signature = params.get("function_signature")
        if address is None or name is None or function_signature is None:
            return {"error": "address, name and function_signature required"}
        return _create_function_pointer(address, name, function_signature)
    elif method == "create_segment":
        address = params.get("address")
        if address is None:
            return {"error": "address required"}
        size = params.get("size", 0x1000)
        name = params.get("name", "created_seg")
        seg_class = params.get("class", "DATA")
        return _create_segment(address, size, name, seg_class)
    elif method == "py_exec":
        code = params.get("code")
        if not code:
            return {"error": "code parameter required"}
        return _py_exec(code)
    else:
        return {"error": f"unknown method {method}"}


def serve():
    global PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Windows 下优先独占端口，避免多个 IDA 进程同时绑定同一个端口。
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except OSError:
            pass
    # 非 Windows 保留 REUSEADDR，便于重启后快速复用 TIME_WAIT 端口。
    if os.name != "nt":
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
    max_tries = 100
    bound = False
    last_error = None
    for _ in range(max_tries):
        try:
            sock.bind((HOST, PORT))
            bound = True
            break
        except OSError as e:
            last_error = e
            PORT += 1
    if not bound:
        print(f"[ida-bridge] bind failed after {max_tries} tries: {last_error}")
        sock.close()
        return
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

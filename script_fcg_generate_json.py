import idc
import ida_auto
import ida_name
import idautils
import json
import re

ida_auto.auto_wait()
dot_input_path = idc.ARGV[1]
json_output_path = dot_input_path.replace(".dot", ".json")

# 建立 function name → address 對照表
func_name_to_ea = {idc.get_func_name(ea): ea for ea in idautils.Functions()}

# 支援 node_id + label 格式，例如：
# "1234" [ label = ".init_proc", ... ]
node_label_re = re.compile(r'"(\w+)"\s+\[\s+label\s*=\s*"([^"]+)"')

node_map = {}

with open(dot_input_path, 'r', encoding='utf-8') as f:
    for line in f:
        match = node_label_re.search(line)
        if match:
            node_id = match.group(1)
            raw_name = match.group(2)

            # 點開頭處理
            prefix = "." if raw_name.startswith(".") else ""
            clean_name = raw_name[1:] if prefix else raw_name
            name_to_lookup = prefix + clean_name  # 查找用（保留點）

            # demangle 用顯示名
            demangled = ida_name.demangle_name(clean_name, ida_name.MNG_SHORT_FORM) or clean_name
            if prefix:
                demangled = prefix + demangled

            # 優先從函式名對照表取得 EA，否則用 get_name_ea_simple
            ea = func_name_to_ea.get(name_to_lookup, idc.get_name_ea_simple(name_to_lookup))

            if ea != idc.BADADDR:
                node_map[node_id] = {
                    "address": hex(ea),
                    "function": demangled
                }
            else:
                print(f"[WARN] No address found for node_id={node_id}, name='{name_to_lookup}'")

# 輸出 JSON
with open(json_output_path, 'w', encoding='utf-8') as out:
    json.dump(node_map, out, indent=2)

print(f"[✓] Address map saved to: {json_output_path}")
idc.qexit(0)

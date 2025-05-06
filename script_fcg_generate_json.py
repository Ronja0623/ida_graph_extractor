import json
import re

import ida_auto
import ida_name
import idautils
import idc

ida_auto.auto_wait()
dot_input_path = idc.ARGV[1]
if dot_input_path.endswith("_raw.dot"):
    json_output_path = dot_input_path.replace("_raw.dot", "_map.json")
else:
    raise ValueError("dot_input_path does not end with '_raw.dot'")


# Create a function name to EA mapping
func_name_to_ea = {idc.get_func_name(ea): ea for ea in idautils.Functions()}

# Set up regex to match node labels in the DOT file
# "1234" [ label = ".init_proc", ... ]
node_label_re = re.compile(r'"(\w+)"\s+\[\s+label\s*=\s*"([^"]+)"')

node_map = {}

with open(dot_input_path, "r", encoding="utf-8") as f:
    for line in f:
        match = node_label_re.search(line)
        if match:
            node_id = match.group(1)
            raw_name = match.group(2)

            # Process the raw name to handle leading dot
            prefix = "." if raw_name.startswith(".") else ""
            clean_name = raw_name[1:] if prefix else raw_name
            name_to_lookup = prefix + clean_name

            # Demangle
            demangled = (
                ida_name.demangle_name(clean_name, ida_name.MNG_SHORT_FORM)
                or clean_name
            )
            if prefix:
                demangled = prefix + demangled

            # Get the address from the function name to EA mapping
            # If the name is not found in the mapping, use get_name_ea_simple
            ea = func_name_to_ea.get(
                name_to_lookup, idc.get_name_ea_simple(name_to_lookup)
            )

            if ea != idc.BADADDR:
                node_map[node_id] = {"address": hex(ea), "function": demangled}
            else:
                print(
                    f"[WARN] No address found for node_id={node_id}, name='{name_to_lookup}'"
                )

# Output the mapping to a JSON file
with open(json_output_path, "w", encoding="utf-8") as out:
    json.dump(node_map, out, indent=2)

print(f"[INFO] Address map saved to: {json_output_path}")
idc.qexit(0)

# copy: python src_code\20250506\script_fcg_replace_node.py output\ida_0506\00a0c872b7379fe4ee505b777b7c866f877dfe17c5a5f8506f1407507bef2d8c\00a0c872b7379fe4ee505b777b7c866f877dfe17c5a5f8506f1407507bef2d8c_raw.dot output\ida_0506\00a0c872b7379fe4ee505b777b7c866f877dfe17c5a5f8506f1407507bef2d8c\00a0c872b7379fe4ee505b777b7c866f877dfe17c5a5f8506f1407507bef2d8c_raw.json output\ida_0506\00a0c872b7379fe4ee505b777b7c866f877dfe17c5a5f8506f1407507bef2d8c\00a0c872b7379fe4ee505b777b7c866f877dfe17c5a5f8506f1407507bef2d8c.dot
import json
import re
import sys

if len(sys.argv) < 4:
    print("Usage: python replace_node_id_in_dot.py <dot_input> <json_map> <dot_output>")
    sys.exit(1)

dot_input_path = sys.argv[1]
json_path = sys.argv[2]
final_dot_path = sys.argv[3]

# Read the JSON mapping file
with open(json_path, "r", encoding="utf-8") as f:
    node_map = json.load(f)

# Read the DOT file
with open(dot_input_path, "r", encoding="utf-8") as f:
    dot_lines = f.readlines()

# Regex patterns to match node labels and edges
node_label_re = re.compile(r'"(\w+)"\s+\[\s+label\s*=\s*"([^"]+)"')
edge_re = re.compile(r'"(\w+)"\s+->\s+"(\w+)"')

new_lines = []
replaced_node_ids = set()

for line in dot_lines:
    stripped = line.strip()

    # Skip empty lines or comments
    if not stripped or stripped.startswith("//"):
        continue

    node_match = node_label_re.search(line)
    edge_match = edge_re.search(line)

    if node_match:
        node_id = node_match.group(1)
        if node_id in node_map:
            replaced_node_ids.add(node_id)
            addr = node_map[node_id]["address"]
            addr_full = f"0x{int(addr, 16):08X}"
            func_name = node_map[node_id]["function"]
            line = f'"{addr_full}" [label="{func_name}"];'

    elif edge_match:
        src, dst = edge_match.groups()
        replaced = False

        if src in node_map:
            src_addr = f'0x{int(node_map[src]["address"], 16):08X}'
            line = re.sub(rf'"{src}"', f'"{src_addr}"', line, count=1)
            replaced_node_ids.add(src)
            replaced = True

        if dst in node_map:
            dst_addr = f'0x{int(node_map[dst]["address"], 16):08X}'
            line = re.sub(rf'"{dst}"', f'"{dst_addr}"', line, count=1)
            replaced_node_ids.add(dst)
            replaced = True

        if not replaced:
            continue  # Skip edges that don't match any node in the map

    new_lines.append(line)

# Clean up the DOT file
clean_lines = []
clean_lines.append("digraph code {\n")

for line in new_lines:
    stripped = line.strip()

    # Remove unnecessary lines
    if stripped in ("graph [", "node [", "edge [", "];"):
        continue
    if stripped.startswith(("graph [", "node [", "edge [")):
        continue

    # Remove unnecessary attributes
    if "pencolor" in stripped:
        line = re.sub(r",?\s*pencolor\s*=\s*\w+", "", line).rstrip()
        if not line.endswith(";"):
            line += ";"
        clean_lines.append(f"  {line.strip()}\n")
        continue

    # Keep only relevant lines
    if re.match(r'^".+?"\s+\[label=".+?"\];?$', stripped) or "->" in stripped:
        if not line.strip().endswith(";"):
            line = line.strip() + ";"
        clean_lines.append(f"  {line.strip()}\n")

clean_lines.append("}\n")

# Write the cleaned DOT file
with open(final_dot_path, "w", encoding="utf-8") as f:
    f.writelines(clean_lines)

# Check for unused node IDs
unused_nodes = set(node_map.keys()) - replaced_node_ids
if unused_nodes:
    print(f"[WARN] Unused node IDs (not found in DOT): {', '.join(unused_nodes)}")

print(f"[✓] Final cleaned DOT written to: {final_dot_path}")

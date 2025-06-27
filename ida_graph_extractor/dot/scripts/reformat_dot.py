import argparse
import json
import re

from utils import get_logger

logger = get_logger(__name__)


def reformat_dot(dot_input_path, json_path, final_dot_path):
    try:
        logger.info(f"Reading node map from: {json_path}")
        with open(json_path, "r", encoding="utf-8") as f:
            node_map = json.load(f)

        logger.info(f"Reading DOT input from: {dot_input_path}")
        with open(dot_input_path, "r", encoding="utf-8") as f:
            dot_lines = f.readlines()

        node_label_re = re.compile(r'"(\w+)"\s+\[\s+label\s*=\s*"([^"]+)"')
        edge_re = re.compile(r'"(\w+)"\s+->\s+"(\w+)"')

        new_lines = []
        replaced_node_ids = set()

        for line in dot_lines:
            stripped = line.strip()
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
                    continue

            new_lines.append(line)

        logger.info("Cleaning DOT file...")
        clean_lines = ["digraph code {\n"]

        for line in new_lines:
            stripped = line.strip()

            if stripped in ("graph [", "node [", "edge [", "];"):
                continue
            if stripped.startswith(("graph [", "node [", "edge [")):
                continue

            if "pencolor" in stripped:
                line = re.sub(r",?\s*pencolor\s*=\s*\w+", "", line).rstrip()
                if not line.endswith(";"):
                    line += ";"
                clean_lines.append(f"  {line.strip()}\n")
                continue

            if re.match(r'^".+?"\s+\[label=".+?"\];?$', stripped) or "->" in stripped:
                if not line.strip().endswith(";"):
                    line = line.strip() + ";"
                clean_lines.append(f"  {line.strip()}\n")

        clean_lines.append("}\n")

        logger.info(f"Writing cleaned DOT to: {final_dot_path}")
        with open(final_dot_path, "w", encoding="utf-8") as f:
            f.writelines(clean_lines)

        unused_nodes = set(node_map.keys()) - replaced_node_ids
        if unused_nodes:
            logger.warning(
                f"Unused node IDs (not found in DOT): {', '.join(unused_nodes)}"
            )

        logger.info("DOT processing completed successfully.")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Replace node IDs in DOT using JSON map."
    )
    parser.add_argument("dot_input", help="Path to raw DOT input file")
    parser.add_argument("json_map", help="Path to node map JSON file")
    parser.add_argument("dot_output", help="Path to output cleaned DOT file")
    args = parser.parse_args()
    reformat_dot(args.dot_input, args.json_map, args.dot_output)

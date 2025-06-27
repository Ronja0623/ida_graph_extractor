import json
import re

import ida_auto
import ida_name
import idautils
import idc

from utils import get_logger

logger = get_logger(__name__)

try:
    ida_auto.auto_wait()

    if len(idc.ARGV) < 3:
        logger.error(
            "Usage: idat -A -Sgenerate_addr_mapping.py <input.dot> <output.json>"
        )
        idc.qexit(1)

    input_dot_path = idc.ARGV[1]
    output_json_path = idc.ARGV[2]

    func_name_to_ea = {idc.get_func_name(ea): ea for ea in idautils.Functions()}
    node_label_re = re.compile(r'"(\w+)"\s+\[\s+label\s*=\s*"([^"]+)"')

    node_map = {}

    with open(input_dot_path, "r", encoding="utf-8") as f:
        for line in f:
            match = node_label_re.search(line)
            if match:
                node_id = match.group(1)
                raw_name = match.group(2)

                prefix = "." if raw_name.startswith(".") else ""
                clean_name = raw_name[1:] if prefix else raw_name
                name_to_lookup = prefix + clean_name

                demangled = (
                    ida_name.demangle_name(clean_name, ida_name.MNG_SHORT_FORM)
                    or clean_name
                )
                if prefix:
                    demangled = prefix + demangled

                ea = func_name_to_ea.get(
                    name_to_lookup, idc.get_name_ea_simple(name_to_lookup)
                )

                if ea != idc.BADADDR:
                    node_map[node_id] = {"address": hex(ea), "function": demangled}
                else:
                    logger.warning(
                        f"No address found for node_id={node_id}, name='{name_to_lookup}'"
                    )

    with open(output_json_path, "w", encoding="utf-8") as out:
        json.dump(node_map, out, indent=2)

    logger.info(f"Address map saved to: {output_json_path}")
    idc.qexit(0)

except Exception as e:
    logger.error(f"An error occurred: {e}", exc_info=True)
    idc.qexit(1)

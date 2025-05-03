import json
import os
import re
from pathlib import Path

from idaapi import *
from idautils import *
from idc import *

LOG_FILE = "log.txt"


def log(msg: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def clean_disasm(disasm_line):
    """Clean disassembly line by collapsing extra spaces."""
    return re.sub(r"\s+", " ", disasm_line.strip())


def demangle(name: str) -> str:
    """Demangle a C++ function name, supporting leading dot notation."""
    if name.startswith("."):
        demangled = demangle_name(name[1:], INF_SHORT_DN)
        return "." + (demangled if demangled else name[1:])
    else:
        demangled = demangle_name(name, INF_SHORT_DN)
        return demangled if demangled else name


def wait_for_analysis():
    """Wait until IDA auto-analysis is complete."""
    log("[INFO] Waiting for IDA analysis to finish...")
    auto_wait()
    log("[INFO] IDA analysis completed.")


def export_cfg(output_path: Path):
    """Export the control flow graph of all functions to a JSON file."""
    os.makedirs(output_path.parent, exist_ok=True)
    log(f"[INFO] Exporting CFG to: {output_path}")

    wait_for_analysis()
    output = {}

    for func_ea in Functions():
        orig_func_name = get_func_name(func_ea)
        func_name = demangle(orig_func_name)
        func = get_func(func_ea)
        if not func:
            continue

        for block in FlowChart(func):
            block_addr = f"0x{block.start_ea:08x}"
            instructions = []

            for insn_ea in range(block.start_ea, block.end_ea):
                if is_code(get_full_flags(insn_ea)):
                    disasm = generate_disasm_line(insn_ea, 0)
                    if disasm:
                        instructions.append(clean_disasm(disasm))

            output[block_addr] = {
                "function_name": func_name,
                "instructions": instructions,
            }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    log(f"[INFO] JSON CFG written to: {output_path}")


# Entry point
try:
    log("[INFO] JSON script started.")

    raw_output = os.environ.get("IDA_OUTPUT", "output.json")
    log(f"[DEBUG] IDA_OUTPUT = {raw_output}")

    output_path = Path(raw_output)
    export_cfg(output_path)

    idaapi.qexit(0)

except Exception as e:
    err_msg = f"[EXCEPTION] {e}"
    with open("cfg_error.txt", "w", encoding="utf-8") as err_file:
        err_file.write(err_msg)
    log(err_msg)
    print(err_msg)
    idaapi.qexit(1)

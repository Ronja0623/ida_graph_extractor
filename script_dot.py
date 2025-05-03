import os
from pathlib import Path

from idaapi import *
from idautils import *
from idc import *

LOG_FILE = "log.txt"


def log(msg: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def format_addr(ea) -> str:
    """Format address to 0xXXXXXXXX (lowercase, 8-digit hex)."""
    return f"0x{ea:08x}"


def demangle(name: str) -> str:
    """Demangle a C++ name if applicable."""
    if name.startswith("."):
        demangled = demangle_name(name[1:], INF_SHORT_DN)
        return "." + (demangled if demangled else name[1:])
    else:
        demangled = demangle_name(name, INF_SHORT_DN)
        return demangled if demangled else name


def get_call_type(ea: int) -> str:
    """Get the mnemonic (instruction type) of the call site."""
    return print_insn_mnem(ea)


def extract_call_edges(func_ea: int):
    """Extract all call-like edges from a given function."""
    edges = []
    func = get_func(func_ea)
    if not func:
        return edges

    for ea in Heads(func.start_ea, func.end_ea):
        if not is_code(get_full_flags(ea)):
            continue
        mnem = print_insn_mnem(ea).lower()
        if mnem.startswith("call") or mnem in ["bl", "blx", "jmp"]:
            target = get_operand_value(ea, 0)
            if target != BADADDR and is_loaded(target):
                edges.append((func_ea, target, ea))
    return edges


def wait_for_analysis():
    """Wait until IDA auto-analysis is complete."""
    log("[INFO] Waiting for IDA analysis to finish...")
    auto_wait()
    log("[INFO] IDA analysis completed.")


def export_fcg(output_path: str):
    """Export function call graph to .dot file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    log(f"[INFO] Exporting to: {output_path}")

    wait_for_analysis()

    function_addrs = set()
    extra_nodes = set()
    edge_count = 0

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("digraph code {\n")

        # Write function nodes (with demangle after analysis)
        for func_ea in Functions():
            addr = format_addr(func_ea)
            label_raw = get_func_name(func_ea)
            label = demangle(label_raw)
            f.write(f'  "{addr}" [label="{label}"];\n')
            function_addrs.add(func_ea)

        # Write call edges
        for func_ea in Functions():
            for caller, callee, call_site in extract_call_edges(func_ea):
                caller_str = format_addr(caller)
                callee_str = format_addr(callee)
                call_site_str = format_addr(call_site)
                call_type = print_insn_mnem(call_site).lower()

                f.write(f'  "{caller_str}" -> "{callee_str}";\n')
                """f.write(
                    f'  "{caller_str}" -> "{callee_str}" [label="{call_site_str} ({call_type})"];\n'
                )"""
                edge_count += 1

                """if callee not in function_addrs and callee not in extra_nodes:
                    f.write(f'  "{callee_str}" [label="UNKNOWN ({callee_str})"];\n')
                    extra_nodes.add(callee)"""

        f.write("}\n")

    log(f"[INFO] Exported {len(function_addrs) + len(extra_nodes)} nodes")
    log(f"[INFO] Exported {edge_count} edges")


# Entry point
try:
    log("[INFO] Script started.")

    raw_output = os.environ.get("IDA_OUTPUT", "output.dot")
    log(f"[DEBUG] IDA_OUTPUT = {raw_output}")

    dot_path = Path(raw_output)
    export_fcg(dot_path)
    idaapi.qexit(0)


except Exception as e:
    err_msg = f"[EXCEPTION] {e}"
    with open("fcg_error.txt", "w", encoding="utf-8") as err_file:
        err_file.write(err_msg)
    log(err_msg)
    print(err_msg)
    idaapi.qexit(1)

import ida_auto
import ida_gdl
import idc

ida_auto.auto_wait()

# Debugging output: print the IDA arguments
print(f"[DEBUG] ARGV: {idc.ARGV}")
if len(idc.ARGV) < 2:
    print("[ERROR] Not enough arguments provided.")
    idc.qexit(1)

dot_output_path = idc.ARGV[1]
print(f"[DEBUG] Writing to: {dot_output_path}")

ida_gdl.gen_simple_call_chart(
    dot_output_path, "Generating chart", "function call graph", ida_gdl.CHART_GEN_DOT
)

print("[INFO] DOT written successfully.")
idc.qexit(0)

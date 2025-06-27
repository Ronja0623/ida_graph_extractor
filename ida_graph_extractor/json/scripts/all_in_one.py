import csv

import ida_auto
import ida_bytes
import ida_ida
import idautils
import idc

from utils import get_logger

logger = get_logger(__name__)

try:
    ida_auto.auto_wait()

    if len(idc.ARGV) < 2:
        logger.error("Usage: idat -A -Ssave_instructions.py <output.csv>")
        idc.qexit(1)

    output_path = idc.ARGV[1]

    start_ea = ida_ida.inf_get_min_ea()
    end_ea = ida_ida.inf_get_max_ea()

    if start_ea == idc.BADADDR or end_ea == idc.BADADDR:
        logger.error("Failed to get start or end address of the binary.")
        idc.qexit(1)

    logger.info(f"Saving disassembled instructions to: {output_path}")

    with open(output_path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.writer(output_file)
        writer.writerow(
            ["Address", "Section", "Function", "Byte Sequence", "Instruction"]
        )

        ea = start_ea
        while ea <= end_ea:
            ins = idautils.DecodeInstruction(ea)
            if ins:
                byte_seq = " ".join(
                    f"{b:02X}" for b in ida_bytes.get_bytes(ins.ea, ins.size)
                )
                disasm = idc.GetDisasm(ea)
                seg_name = idc.get_segm_name(ea)
                func_name = idc.get_func_name(ea)

                writer.writerow([hex(ea), seg_name, func_name, byte_seq, disasm])
            ea = idc.next_head(ea, end_ea)

    logger.info(f"Instructions successfully saved to: {output_path}")
    idc.qexit(0)

except Exception as e:
    logger.error(f"An error occurred: {e}", exc_info=True)
    idc.qexit(1)

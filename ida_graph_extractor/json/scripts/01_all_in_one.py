import csv

import ida_auto
import ida_bytes
import ida_ida
import idautils
import idc

from ..utils import get_logger

# Set up logging
logger = get_logger(__name__)

try:
    logger.info("Waiting for IDA auto analysis to complete...")
    ida_auto.auto_wait()

    start = ida_ida.inf_get_min_ea()
    end = ida_ida.inf_get_max_ea()
    output_path = idc.ARGV[1]

    if start == idc.BADADDR or end == idc.BADADDR:
        logger.error("Failed to get function start and end addresses.")
        idc.qexit(1)

    logger.info(f"Saving disassembled instructions to: {output_path}")

    with open(output_path, "w", newline="") as output_file:
        writer = csv.writer(output_file)
        writer.writerow(
            ["Address", "Section", "Function", "Byte Sequence", "Instruction"]
        )

        curr_addr = start
        while curr_addr <= end:
            ins = idautils.DecodeInstruction(curr_addr)
            if ins:
                byte_seq = " ".join(
                    f"{b:02X}" for b in ida_bytes.get_bytes(ins.ea, ins.size)
                )
                disasm = idc.GetDisasm(curr_addr)
                seg = idc.get_segm_name(curr_addr)
                func_name = idc.get_func_name(curr_addr)

                writer.writerow([hex(curr_addr), seg, func_name, byte_seq, disasm])
            curr_addr = idc.next_head(curr_addr, end)

    logger.info(f"Instructions successfully saved to: {output_path}")

except Exception as e:
    logger.error(f"An error occurred: {e}", exc_info=True)
    idc.qexit(1)

idc.qexit(0)

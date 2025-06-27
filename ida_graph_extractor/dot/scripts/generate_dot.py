import ida_auto
import ida_gdl
import idc

from utils import get_logger

logger = get_logger(__name__)

try:
    logger.info("Waiting for IDA auto analysis to complete...")
    ida_auto.auto_wait()

    if len(idc.ARGV) < 2:
        logger.error(
            "Output path not specified. Usage: idat -A -Sgenerate_dot.py <output.dot>"
        )
        idc.qexit(1)

    output_dot_path = idc.ARGV[1]
    logger.info(f"Generating call graph to DOT file: {output_dot_path}")

    ida_gdl.gen_simple_call_chart(
        output_dot_path,
        "Generating chart",
        "function call graph",
        ida_gdl.CHART_GEN_DOT,
    )

    logger.info(f"Call graph saved to: {output_dot_path}")

except Exception as e:
    logger.error(f"An error occurred: {e}", exc_info=True)
    idc.qexit(1)

idc.qexit(0)

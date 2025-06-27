import os
import subprocess
import sys
from pathlib import Path

from ..utils import get_logger, run_subprocess

logger = get_logger(__name__)

IDA_PATH = "/path/to/idat64"  # 修改為你的 IDA 路徑
IDA_SCRIPT = "scripts/extract_instructions.py"  # 產生 CSV 的 IDA script
PYTHON_SCRIPT = "scripts/csv_to_instruction_json.py"  # 將 CSV 轉為 JSON


def main(binary_path):
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    csv_output_path = output_dir / "instructions.csv"
    json_output_path = output_dir / "instructions.json"

    # 1. Run IDA to dump disassembled instructions to CSV
    run_subprocess(
        [IDA_PATH, "-A", f"-S{IDA_SCRIPT} {csv_output_path}", binary_path],
        "Extracting disassembled instructions (CSV) via IDA",
    )

    # 2. Run script to convert CSV to JSON
    run_subprocess(
        [sys.executable, PYTHON_SCRIPT, str(csv_output_path), str(json_output_path)],
        "Converting CSV to JSON",
    )

    logger.info(
        f"[Complete] Instruction pipeline finished. JSON output: {json_output_path}"
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        logger.error("Usage: python run_instruction_pipeline.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    if not os.path.isfile(binary_path):
        logger.error(f"Binary file not found: {binary_path}")
        sys.exit(1)

    main(binary_path)

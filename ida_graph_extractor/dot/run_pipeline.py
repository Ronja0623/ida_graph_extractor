import argparse
import subprocess
import sys
import os
from pathlib import Path
from utils.logger import get_logger
from scripts.reformat_dot import reformat_dot

logger = get_logger(__name__)

IDA_EXECUTABLE = "ida64.exe"  # Modify this path as needed

def run_ida_script(ida_script: Path, binary_path: Path, *script_args):
    """
    Run an IDA Python script with given arguments in headless mode.
    """
    full_command = [
        IDA_EXECUTABLE,
        "-A",
        f"-S{ida_script} {' '.join(map(str, script_args))}",
        str(binary_path)
    ]

    logger.info(f"Running IDA script: {' '.join(full_command)}")
    try:
        subprocess.run(full_command, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"IDA script {ida_script.name} failed.", exc_info=True)
        sys.exit(1)

def main(output_dir: Path, binary_path: Path):
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_dot_path = output_dir / "callgraph_raw.dot"
    json_map_path = output_dir / "node_map.json"
    final_dot_path = output_dir / "callgraph_final.dot"

    script_dir = Path(__file__).parent / "scripts"
    dot_script = script_dir / "generate_dot.py"
    map_script = script_dir / "generate_addr_mapping.py"

    logger.info("Step 1: Generate raw DOT via IDA")
    run_ida_script(dot_script, binary_path, raw_dot_path)

    if not raw_dot_path.exists():
        logger.error(f"DOT file not generated: {raw_dot_path}")
        sys.exit(1)

    logger.info("Step 2: Generate node mapping via IDA")
    run_ida_script(map_script, binary_path, raw_dot_path, json_map_path)

    if not json_map_path.exists():
        logger.error(f"JSON mapping not generated: {json_map_path}")
        sys.exit(1)

    logger.info("Step 3: Reformat DOT with readable names")
    reformat_dot(raw_dot_path, json_map_path, final_dot_path)

    logger.info("Pipeline completed successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DOT Graph Pipeline Runner")
    parser.add_argument(
        "-o", "--output", type=str, default="output",
        help="Output directory for generated files"
    )
    parser.add_argument(
        "--binary", type=str, required=True,
        help="Path to the binary to analyze with IDA"
    )
    args = parser.parse_args()

    main(Path(args.output), Path(args.binary))

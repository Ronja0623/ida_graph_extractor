import argparse
import sys
from pathlib import Path

from scripts.reformat_dot import reformat_dot
from utils import get_logger, run_ida_script

logger = get_logger(__name__)


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
        "-o",
        "--output",
        type=str,
        default="output",
        help="Output directory for generated files",
    )
    parser.add_argument(
        "--binary",
        type=str,
        required=True,
        help="Path to the binary to analyze with IDA",
    )
    args = parser.parse_args()

    main(Path(args.output), Path(args.binary))

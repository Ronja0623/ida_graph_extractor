import argparse
import sys
from pathlib import Path

from utils import get_logger, run_ida_script

logger = get_logger(__name__)


def main(output_dir: Path, binary_path: Path):
    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        csv_output_path = output_dir / "instructions.csv"
        json_output_path = output_dir / "instructions.json"

        script_dir = Path(__file__).parent / "scripts"
        csv_script = script_dir / "01_all_in_one.py"
        instruct_collect_script = script_dir / "02_collect_instruct.py"

        logger.info("Step 1: Extract instructions to CSV via IDA")
        run_ida_script(csv_script, binary_path, csv_output_path)

        if not csv_output_path.exists():
            logger.error(f"CSV file not generated: {csv_output_path}")
            sys.exit(1)

        logger.info("Step 2: Convert CSV to JSON")
        run_subprocess(
            [
                sys.executable,
                instruct_collect_script,
                str(csv_output_path),
                str(json_output_path),
            ],
            "Converting CSV to JSON",
        )

        if not json_output_path.exists():
            logger.error(f"JSON file not generated: {json_output_path}")
            sys.exit(1)

        logger.info(f"Pipeline completed successfully. JSON output: {json_output_path}")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Instruction Extraction Pipeline Runner"
    )
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

    binary_path = Path(args.binary)
    if not binary_path.is_file():
        logger.error(f"Binary file not found: {binary_path}")
        sys.exit(1)

    main(Path(args.output), binary_path)

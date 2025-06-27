import argparse
import csv
import json
from collections import defaultdict

from utils import get_logger

logger = get_logger(__name__)


def csv_to_json(csv_path, output_json_path):
    try:
        logger.info(f"Reading CSV: {csv_path}")
        function_map = defaultdict(lambda: {"function_name": "", "instructions": []})

        with open(csv_path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                address = row["Address"]
                func_name = row["Function"]
                instruction = row["Instruction"]

                if not func_name or not instruction:
                    continue

                function_map[address]["function_name"] = func_name
                function_map[address]["instructions"].append(instruction)

        logger.info(f"Writing JSON output to: {output_json_path}")
        with open(output_json_path, "w", encoding="utf-8") as outfile:
            json.dump(function_map, outfile, indent=2)

        logger.info("JSON generation completed successfully.")

    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert CSV of instructions to JSON format grouped by function."
    )
    parser.add_argument("input_csv", help="Path to input CSV file")
    parser.add_argument("output_json", help="Path to output JSON file")
    args = parser.parse_args()

    csv_to_json(args.input_csv, args.output_json)

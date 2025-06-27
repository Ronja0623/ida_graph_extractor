import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

from ...utils import get_logger

logger = get_logger(__name__)

if len(sys.argv) < 3:
    logger.error("Usage: python csv_to_instruction_json.py <input_csv> <output_json>")
    sys.exit(1)

csv_path = sys.argv[1]
output_json_path = sys.argv[2]

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
    sys.exit(1)

sys.exit(0)

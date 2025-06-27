# Instruction Extraction Pipeline Runner

This project provides a simple pipeline to analyze a binary file with IDA Pro, extract instructions into a CSV file, and then convert that CSV into a JSON file for further processing.

## Features

- **Automated pipeline** to:
  - Extract instructions from a binary using IDA Pro.
  - Save instructions in CSV format.
  - Convert the CSV output into a structured JSON file by calling a local Python module.
- Handles errors gracefully with clear logging.

## Requirements

- Python 3.7+
- IDA Pro (with command-line execution capabilities)
- Required IDA Python scripts:
  - `scripts/all_in_one.py` (IDA extraction script)
  - `scripts/collect_instruct.py` (CSV to JSON converter)

## Usage

Run the pipeline script from the command line:

```bash
python your_script.py --binary /path/to/binary -o /path/to/output_dir

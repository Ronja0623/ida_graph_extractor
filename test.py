import os
import subprocess
from pathlib import Path

LOG_FILE = "log.txt"


def log(msg: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def run_ida(script_path, input_file, output_file):
    """Run IDA with the given script and output target."""
    env = os.environ.copy()
    env["IDA_OUTPUT"] = str(output_file)

    command = [
        "idat64.exe",  # Replace with full path if needed
        "-A",
        "-c",
        f'-S"{script_path}"',
        input_file,
    ]

    log(f"[INFO] Running: {script_path}")
    log(f"[INFO] Output: {output_file}")

    try:
        subprocess.run(command, env=env, check=True)
        log(f"[SUCCESS] Completed: {output_file}")
    except subprocess.CalledProcessError as e:
        log(f"[ERROR] IDA failed for script: {script_path}")
        log(f"[ERROR] {e}")
    except Exception as e:
        log(f"[EXCEPTION] Unexpected error: {e}")


# Entry point
## Script path
dot_script = "script_dot.py"
json_script = "script_json.py"
## Input path
input_file = r"C:\Document\Dataset\dataset202503\dataset202503\00a0c872b7379fe4ee505b777b7c866f877dfe17c5a5f8506f1407507bef2d8c"
input_name = Path(input_file).name
## Output path
output_base = Path("output") / input_name
output_base.mkdir(parents=True, exist_ok=True)
json_output = output_base / f"{input_name}.json"
dot_output = output_base / f"{input_name}.dot"

# Analysis
run_ida(json_script, input_file, json_output)
run_ida(dot_script, input_file, dot_output)

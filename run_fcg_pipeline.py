import os
import subprocess
import sys
from pathlib import Path

LOG_FILE = "log.txt"


def log(msg: str):
    print(msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def run_ida(script_path, input_file, output_file):
    """Run IDA with a single output file parameter."""
    env = os.environ.copy()

    script_path = str(script_path)
    input_file = str(input_file)
    output_file = str(output_file)

    command = ["idat64.exe", "-A", "-c", f"-S{script_path} {output_file}", input_file]

    log(f"\n[INFO] === Running IDA ===")
    log(f"[INFO] Script: {script_path}")
    log(f"[INFO] Input: {input_file}")
    log(f"[INFO] Output: {output_file}")
    log(f"[INFO] Command: {' '.join(command)}")

    try:
        result = subprocess.run(
            command, env=env, capture_output=True, text=True, check=True
        )
        log(f"[SUCCESS] Completed: {output_file}")
        if result.stdout:
            log("[STDOUT]\n" + result.stdout)
        if result.stderr:
            log("[STDERR]\n" + result.stderr)
    except subprocess.CalledProcessError as e:
        log(f"[ERROR] IDA failed for script: {script_path}")
        log(f"[STDERR]\n{e.stderr}")
    except Exception as e:
        log(f"[EXCEPTION] Unexpected error: {e}")


def run_replace_node(dot_raw, json_map, dot_final, script_path):
    """Run node replacement script using Python, not IDA."""
    args = [sys.executable, script_path, str(dot_raw), str(json_map), str(dot_final)]

    log(f"\n[INFO] === Running replace_node (pure Python) ===")
    log(f"[INFO] Script: {script_path}")
    log(f"[INFO] Args: {args}")

    try:
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        log(f"[SUCCESS] Node replacement completed.")
        if result.stdout:
            log("[STDOUT]\n" + result.stdout)
        if result.stderr:
            log("[STDERR]\n" + result.stderr)
    except subprocess.CalledProcessError as e:
        log(f"[ERROR] Replace script failed.")
        log(f"[STDERR]\n{e.stderr}")
    except Exception as e:
        log(f"[EXCEPTION] Unexpected error: {e}")


def clean_intermediate_files(*paths):
    """Remove intermediate files such as raw .dot and .json"""
    for path in paths:
        path = Path(path)
        try:
            if path.exists():
                path.unlink()
                log(f"[CLEANUP] Removed: {path}")
            else:
                log(f"[CLEANUP] Skipped (not found): {path}")
        except Exception as e:
            log(f"[ERROR] Failed to remove {path}: {e}")


# === Script paths ===
script_generate_dot = r"ida_graph_extractor\script_fcg_generate_dot.py"
script_generate_json = r"ida_graph_extractor\script_fcg_generate_json.py"
script_replace_node = r"ida_graph_extractor\script_fcg_replace_node.py"

# === Input target binary ===
input_file = r"Dataset\dataset202503\dataset202503\00a0c872b7379fe4ee505b777b7c866f877dfe17c5a5f8506f1407507bef2d8c"
input_name = Path(input_file).name
output_base = Path("output") / input_name
output_base.mkdir(parents=True, exist_ok=True)

# === Output file paths ===
dot_raw = output_base / f"{input_name}_raw.dot"
json_map = output_base / f"{input_name}_map.json"
dot_final = output_base / f"{input_name}.dot"

# === Run IDA scripts ===
run_ida(script_generate_dot, input_file, dot_raw)
run_ida(script_generate_json, input_file, dot_raw)

# === Run node ID → address replacement (pure Python) ===
run_replace_node(dot_raw, json_map, dot_final, script_replace_node)

# === Clean intermediate files ===
clean_intermediate_files(dot_raw, json_map)

print(f"\n[INFO] Pipeline completed.\nResults in: {output_base}")

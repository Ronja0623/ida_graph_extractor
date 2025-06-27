import subprocess
import sys
from pathlib import Path


def run_pipeline_test():
    """
    Execute run_pipeline.py with a temporary output directory.
    """
    script_path = Path(__file__).parent / "dot" / "run_pipeline.py"
    output_dir = Path(__file__).parent / "test_output"

    print(f"[*] Running pipeline with output: {output_dir}")
    try:
        result = subprocess.run(
            [sys.executable, str(script_path), "-o", str(output_dir)],
            capture_output=True,
            text=True,
            check=True,
        )

        print("[+] Pipeline ran successfully.")
        print("==== STDOUT ====")
        print(result.stdout)
        print("==== STDERR ====")
        print(result.stderr)

    except subprocess.CalledProcessError as e:
        print("[!] Pipeline execution failed.")
        print("==== STDOUT ====")
        print(e.stdout)
        print("==== STDERR ====")
        print(e.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run_pipeline_test()

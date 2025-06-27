import subprocess
import sys
from pathlib import Path

from utils.logger import get_logger

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
        str(binary_path),
    ]

    logger.info(f"Running IDA script: {' '.join(full_command)}")
    try:
        subprocess.run(full_command, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"IDA script {ida_script.name} failed.", exc_info=True)
        sys.exit(1)

import logging
import sys
from typing import Optional


def get_logger(
    name: str,
    level: int = logging.INFO,
    to_file: Optional[str] = None,
    fmt: Optional[str] = None,
) -> logging.Logger:
    """
    Create and return a configured logger.

    Args:
        name (str): Logger name (usually __name__)
        level (int): Logging level (default: INFO)
        to_file (str): If set, logs will be written to this file
        fmt (str): Custom log format (optional)

    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(name)

    if logger.hasHandlers():
        return logger  # Avoid adding duplicate handlers

    logger.setLevel(level)

    # Default log format
    if fmt is None:
        fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    formatter = logging.Formatter(fmt)

    # Choose output destination
    if to_file:
        handler = logging.FileHandler(to_file)
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

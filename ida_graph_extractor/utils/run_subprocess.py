def run_subprocess(command, description):
    logger.info(f"[Step] {description}")
    try:
        subprocess.run(command, check=True)
        logger.info(f"[Success] {description}")
    except subprocess.CalledProcessError as e:
        logger.error(f"[Failed] {description}: {e}")
        sys.exit(1)

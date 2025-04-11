import os
import logging

# Define log file path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.dirname(CURRENT_DIR)
log_file = os.path.join(PATH, "voip.log")

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),  # Ensure UTF-8 for file logs
        logging.StreamHandler(),  # Console logs (fix below for Windows)
    ],
)

# Create a logger instance
logger = logging.getLogger("agi_logger")
# 🔹 Disable logs from external libraries
logging.getLogger().setLevel(logging.WARNING)  # Blocks DEBUG & INFO from all libraries
logger.setLevel(logging.DEBUG)

# Fix encoding issue for Windows console
import sys
if sys.platform.startswith("win"):
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")

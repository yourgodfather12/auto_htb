import logging
import os
from rich.console import Console
from config_loader import OUTPUT_DIR  # Ensure OUTPUT_DIR is imported from config_loader

# Initialize rich console
console = Console()

# Setup logging
LOG_FILE = os.path.join(OUTPUT_DIR, 'tool.log')
logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def log_error(message: str) -> None:
    logger.error(message)
    console.print(f"[bold red]{message}[/bold red]")

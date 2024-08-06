import os
import json

# Load configuration from file
CONFIG_FILE = "config.json"

try:
    with open(CONFIG_FILE, 'r') as file:
        config = json.load(file)
except FileNotFoundError:
    print(f"Configuration file {CONFIG_FILE} not found.")
    exit(1)
except json.JSONDecodeError:
    print(f"Error decoding JSON from the configuration file {CONFIG_FILE}.")
    exit(1)

# Configuration setup
OUTPUT_DIR = config.get("output_dir", "results")
ROCKYOU_WORDLIST = config.get("rockyou_wordlist", "/usr/share/wordlists/rockyou.txt")
DIRBUSTER_WORDLIST = config.get("dirbuster_wordlist", "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt")
REQUIRED_TOOLS = config.get("required_tools", [])
SCAN_RATE = config.get("scan_rate", 2)
RANDOMIZE = config.get("randomize", True)
STEALTH_MODE = config.get("stealth_mode", True)

# Ensure the output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

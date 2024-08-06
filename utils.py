import os
import subprocess
import platform
from config import console, log_error
from config_loader import REQUIRED_TOOLS, ROCKYOU_WORDLIST, DIRBUSTER_WORDLIST


def check_tool_availability(tool: str) -> bool:
    try:
        result = subprocess.run(f"where {tool}" if platform.system() == "Windows" else f"command -v {tool}", shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.returncode == 0
    except subprocess.SubprocessError as e:
        log_error(f"Error checking availability of {tool}: {e}")
        return False


def ensure_sudo() -> None:
    if platform.system() == "Windows":
        console.print("[bold yellow]Running on Windows, skipping sudo checks.[/bold yellow]")
        return

    if not check_tool_availability("sudo"):
        console.print(f"[bold red]sudo is not installed. Please install sudo and configure it correctly.[/bold red]")
        exit(1)

    try:
        result = subprocess.run("sudo -v", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            console.print(f"[bold red]sudo is not configured correctly. Ensure you have sudo privileges.[/bold red]")
            exit(1)
    except subprocess.SubprocessError as e:
        log_error(f"Error checking sudo configuration: {e}")
        console.print(
            f"[bold red]Error checking sudo configuration. Please ensure sudo is configured correctly.[/bold red]")
        exit(1)


def ensure_permissions() -> None:
    if platform.system() == "Windows":
        return

    if os.geteuid() != 0:
        console.print(f"[bold red]This script requires root privileges. Please run it with sudo.[/bold red]")
        exit(1)


def install_tool(tool: str) -> None:
    if platform.system() == "Windows":
        console.print(
            f"[bold red]Automatic installation not supported on Windows. Please install {tool} manually.[/bold red]")
        return

    ensure_permissions()
    try:
        console.print(f"[bold yellow]Installing {tool}...[/bold yellow]")
        result = subprocess.run(f"sudo apt-get install -y {tool}", shell=True, check=True, stderr=subprocess.STDOUT)
        if result.returncode == 0:
            console.print(f"[bold green]{tool} installed successfully.[/bold green]")
        else:
            log_error(f"Error installing {tool}: Installation failed with return code {result.returncode}.")
            console.print(f"[bold red]Error installing {tool}. Please install it manually.[/bold red]")
            exit(1)
    except subprocess.CalledProcessError as e:
        log_error(f"Error installing {tool}: {e}")
        console.print(f"[bold red]Error installing {tool}. Please install it manually.[/bold red]")
        exit(1)


def check_and_install_tools() -> None:
    ensure_sudo()
    ensure_permissions()
    for tool in REQUIRED_TOOLS:
        if not check_tool_availability(tool):
            install_tool(tool)
        else:
            console.print(f"[bold green]{tool} is already installed.[/bold green]")


def ensure_wordlists() -> None:
    if not os.path.exists(ROCKYOU_WORDLIST):
        console.print(
            f"[bold yellow]rockyou.txt not found. Please download it and place it in /usr/share/wordlists.[/bold yellow]")
        log_error(f"Missing wordlist: {ROCKYOU_WORDLIST}")
        exit(1)
    if not os.path.exists(DIRBUSTER_WORDLIST):
        console.print(
            f"[bold yellow]SecLists not found. Please download SecLists from "
            f"https://github.com/danielmiessler/SecLists and place it in /usr/share/seclists.[/bold yellow]")
        log_error(f"Missing wordlist: {DIRBUSTER_WORDLIST}")
        exit(1)


if __name__ == "__main__":
    check_and_install_tools()
    ensure_wordlists()

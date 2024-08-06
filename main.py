import os
import signal
import re
from multiprocessing import Pool
from config import console, OUTPUT_DIR, log_error
from utils import check_and_install_tools, ensure_wordlists
from scanning import (
    amass_subdomain_enumeration, sublist3r_subdomain_enumeration, theharvester_osint,
    nmap_scan, gobuster_directory_scan, nikto_scan, wpscan_scan, sqlmap_scan,
    jsparser_scan, ffuf_fuzzing, searchsploit_scan, enum4linux_scan, hydra_brute_force
)
from results import extract_info_from_nmap, extract_directories_from_gobuster

def get_target_domain() -> str:
    return input("Enter the target domain: ").strip()

def signal_handler(sig, frame) -> None:
    console.print("\n[bold red]Script interrupted. Cleaning up...[/bold red]")
    exit(0)

def run_scan(target_domain: str) -> None:
    signal.signal(signal.SIGINT, signal_handler)
    global OUTPUT_DIR

    OUTPUT_DIR = os.path.join(OUTPUT_DIR, target_domain)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    try:
        check_and_install_tools()
        ensure_wordlists()

        nmap_output = nmap_scan(target_domain)
        services, service_versions = extract_info_from_nmap(nmap_output)
        target_ip = None

        for service in service_versions:
            if 'target_ip' in service:
                target_ip = service['target_ip']

        if not target_ip:
            console.print("[bold red]Failed to resolve target IP address.[/bold red]")
            return

        tasks = [
            (amass_subdomain_enumeration, target_domain),
            (sublist3r_subdomain_enumeration, target_domain),
            (theharvester_osint, target_domain),
            (lambda: nmap_scan(target_domain), target_domain)
        ]

        with Pool(processes=4) as pool:
            results = pool.starmap(lambda f, arg: f(arg), tasks)
            nmap_output = results[3]
            services, service_versions = extract_info_from_nmap(nmap_output)

        http_services = [service for service in services if 'http' in service.lower()]
        if http_services:
            gobuster_output = gobuster_directory_scan(target_ip)
            directories = extract_directories_from_gobuster(gobuster_output)
            nikto_scan(target_ip)

            if any('wp-' in directory for directory in directories):
                wpscan_scan(target_ip)

            sql_injection_candidates = [directory for directory in directories if
                                        re.search(r'\b(login|search|id)\b', directory)]
            if sql_injection_candidates:
                sqlmap_scan(target_ip, sql_injection_candidates)

            js_files = [directory for directory in directories if directory.endswith('.js')]
            if js_files:
                jsparser_scan(target_ip, js_files)

            ffuf_fuzzing(target_ip)
        else:
            directories = []

        searchsploit_scan(services, target_ip)

        smb_services = [service for service in services if 'smb' in service.lower() or 'netbios' in service.lower()]
        if smb_services:
            enum4linux_scan(target_ip)

        login_directories = [directory for directory in directories if 'login' in directory]
        if login_directories:
            hydra_brute_force(target_ip, login_directories)

        console.print(f"\n[bold green]Scanning and enumeration completed. Results saved in {OUTPUT_DIR}[/bold green]")

    except Exception as e:
        log_error(f"An error occurred: {e}")

if __name__ == "__main__":
    target_domain = get_target_domain()
    run_scan(target_domain)

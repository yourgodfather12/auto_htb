import os
import subprocess
import re
import time
import random
from config import console, log_error
from config_loader import OUTPUT_DIR, DIRBUSTER_WORDLIST, ROCKYOU_WORDLIST, SCAN_RATE, RANDOMIZE, STEALTH_MODE
from results import search_cves, extract_info_from_nmap, extract_directories_from_gobuster
from rich.progress import Progress, SpinnerColumn, BarColumn

def run_command(command: str, output_file: str, description: str) -> str:
    try:
        with Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                console=console
        ) as progress:
            task = progress.add_task(f"[cyan]{description}", total=100)
            result = subprocess.run(command, shell=True, text=True, capture_output=True)
            with open(output_file, "w") as f:
                f.write(result.stdout)
            with open(os.path.join(OUTPUT_DIR, "results.txt"), "a") as result_file:
                result_file.write(f"## {description} ##\n")
                result_file.write(result.stdout)
                result_file.write("\n\n")
            progress.update(task, advance=100)
            if result.returncode != 0:
                log_error(f"Error running {description}: {result.stderr}")
            return result.stdout
    except subprocess.CalledProcessError as e:
        log_error(f"Command '{command}' failed: {e}")
        return ""
    except Exception as e:
        log_error(f"Error running {description}: {e}")
        return ""

def apply_stealth():
    if STEALTH_MODE:
        time.sleep(random.uniform(0, SCAN_RATE))

def amass_subdomain_enumeration(target_domain: str) -> bool:
    console.print("[bold cyan]Running Amass for subdomain enumeration...[/bold cyan]")
    amass_command = f"amass enum -d {target_domain} -o {os.path.join(OUTPUT_DIR, 'amass_results.txt')}"
    run_command(amass_command, os.path.join(OUTPUT_DIR, 'amass_results.txt'), "Amass Subdomain Enumeration")
    console.print("[bold green]Amass subdomain enumeration completed.[/bold green]")
    apply_stealth()
    return True

def sublist3r_subdomain_enumeration(target_domain: str) -> bool:
    console.print("[bold cyan]Running Sublist3r for subdomain enumeration...[/bold cyan]")
    sublist3r_command = f"sublist3r -d {target_domain} -o {os.path.join(OUTPUT_DIR, 'sublist3r_results.txt')}"
    run_command(sublist3r_command, os.path.join(OUTPUT_DIR, 'sublist3r_results.txt'), "Sublist3r Subdomain Enumeration")
    console.print("[bold green]Sublist3r subdomain enumeration completed.[/bold green]")
    apply_stealth()
    return True

def theharvester_osint(target_domain: str) -> bool:
    console.print("[bold cyan]Running theHarvester for OSINT gathering...[/bold cyan]")
    theharvester_command = f"theHarvester -d {target_domain} -l 500 -b all -f {os.path.join(OUTPUT_DIR, 'theHarvester_results.html')}"
    run_command(theharvester_command, os.path.join(OUTPUT_DIR, 'theHarvester_results.html'), "theHarvester OSINT Gathering")
    console.print("[bold green]theHarvester OSINT gathering completed.[/bold green]")
    apply_stealth()
    return True

def nmap_scan(target_ip: str) -> str:
    console.print("[bold cyan]Running Nmap scan...[/bold cyan]")
    nmap_command = f"nmap -sS -T{SCAN_RATE} -Pn -oA {os.path.join(OUTPUT_DIR, 'initial_scan')} {target_ip}"
    nmap_output = run_command(nmap_command, os.path.join(OUTPUT_DIR, 'nmap_scan.txt'), "Nmap Scan")
    console.print("[bold green]Nmap scan completed.[/bold green]")
    apply_stealth()
    return nmap_output

def gobuster_directory_scan(target_ip: str) -> str:
    console.print("[bold cyan]Running Gobuster for directory and file brute-forcing...[/bold cyan]")
    gobuster_command = f"gobuster dir -u https://{target_ip} -w {DIRBUSTER_WORDLIST} -o {os.path.join(OUTPUT_DIR, 'gobuster_results.txt')} -z"
    gobuster_output = run_command(gobuster_command, os.path.join(OUTPUT_DIR, 'gobuster_results.txt'), "Gobuster Directory Scan")
    console.print("[bold green]Gobuster scan completed.[/bold green]")
    apply_stealth()
    return gobuster_output

def nikto_scan(target_ip: str) -> None:
    console.print("[bold cyan]Running Nikto for web server scanning...[/bold cyan]")
    nikto_command = f"nikto -h https://{target_ip} -output {os.path.join(OUTPUT_DIR, 'nikto_results.txt')}"
    run_command(nikto_command, os.path.join(OUTPUT_DIR, 'nikto_results.txt'), "Nikto Web Server Scan")
    console.print("[bold green]Nikto scan completed.[/bold green]")
    apply_stealth()

def wpscan_scan(target_ip: str) -> bool:
    console.print("[bold cyan]Running WPScan for WordPress vulnerability scanning...[/bold cyan]")
    wpscan_command = f"wpscan --url https://{target_ip} --output {os.path.join(OUTPUT_DIR, 'wpscan_results.txt')}"
    run_command(wpscan_command, os.path.join(OUTPUT_DIR, 'wpscan_results.txt'), "WPScan")
    console.print("[bold green]WPScan completed.[/bold green]")
    apply_stealth()
    return True

def sqlmap_scan(target_ip: str, sql_injection_candidates: list) -> None:
    console.print("[bold cyan]Running SQLMap for SQL injection testing...[/bold cyan]")
    for candidate in sql_injection_candidates:
        sqlmap_command = f"sqlmap -u https://{target_ip}/{candidate} --batch --output-dir={os.path.join(OUTPUT_DIR, 'sqlmap_results')}"
        run_command(sqlmap_command, os.path.join(OUTPUT_DIR, f'sqlmap_results_{candidate}.txt'), f"SQLMap - {candidate}")
        apply_stealth()
    console.print("[bold green]SQLMap scan completed.[/bold green]")

def jsparser_scan(target_ip: str, js_files: list) -> None:
    console.print("[bold cyan]Running JSParser for JavaScript endpoint discovery...[/bold cyan]")
    for js_file in js_files:
        jsparser_command = f"python3 JSParser.py -u https://{target_ip}/{js_file} -o {os.path.join(OUTPUT_DIR, 'jsparser_results.txt')}"
        run_command(jsparser_command, os.path.join(OUTPUT_DIR, 'jsparser_results.txt'), f"JSParser - {js_file}")
        apply_stealth()
    console.print("[bold green]JSParser completed.[/bold green]")

def ffuf_fuzzing(target_ip: str) -> None:
    console.print("[bold cyan]Running ffuf for URL and parameter fuzzing...[/bold cyan]")
    ffuf_command = f"ffuf -u https://{target_ip}/FUZZ -w {DIRBUSTER_WORDLIST} -o {os.path.join(OUTPUT_DIR, 'ffuf_results.json')} -z"
    run_command(ffuf_command, os.path.join(OUTPUT_DIR, 'ffuf_results.json'), "ffuf URL Fuzzing")
    apply_stealth()
    console.print("[bold green]ffuf URL fuzzing completed.[/bold green]")

def metasploit_exploit(cve: str, target_ip: str) -> None:
    try:
        msfconsole_command = f"""
        use auxiliary/scanner/vulnerabilities/ghdb_cve_search
        set CVE {cve}
        set RHOSTS {target_ip}
        run
        """
        subprocess.run(['msfconsole', '-q', '-x', msfconsole_command], check=True)
    except Exception as e:
        log_error(f"Error running Metasploit for CVE {cve}: {e}")

def searchsploit_scan(services: list, target_ip: str) -> None:
    console.print("[bold cyan]Running SearchSploit for exploit searches...[/bold cyan]")
    for service in services:
        service_name, version = service.split()
        searchsploit_command = f"searchsploit {service_name} {version}"
        searchsploit_output = run_command(searchsploit_command,
                                          os.path.join(OUTPUT_DIR, f'searchsploit_{service_name}_{version}.txt'),
                                          f"SearchSploit - {service_name} {version}")

        cves = search_cves(service_name, version)
        if cves:
            with open(os.path.join(OUTPUT_DIR, f'cves_{service_name}_{version}.txt'), "w") as f:
                for cve in cves:
                    f.write(f"CVE ID: {cve['id']}\n")
                    f.write(f"Summary: {cve['summary']}\n\n")
            console.print(f"[bold green]CVEs found for {service_name} {version}: {', '.join([cve['id'] for cve in cves])}[/bold green]")

            first_cve = cves[0]['id']
            console.print(f"[bold cyan]Attempting to exploit CVE {first_cve} using Metasploit...[/bold cyan]")
            metasploit_exploit(first_cve, target_ip)
        else:
            console.print(f"[bold yellow]No CVEs found for {service_name} {version}[/bold yellow]")

def enum4linux_scan(target_ip: str) -> None:
    console.print("[bold cyan]Running enum4linux for Windows enumeration...[/bold cyan]")
    enum4linux_command = f"enum4linux -a {target_ip} -o {os.path.join(OUTPUT_DIR, 'enum4linux_results.txt')}"
    run_command(enum4linux_command, os.path.join(OUTPUT_DIR, 'enum4linux_results.txt'), "Enum4linux Scan")
    console.print("[bold green]Enum4linux scan completed.[/bold green]")

def hydra_brute_force(target_ip: str, login_directories: list) -> None:
    console.print("[bold cyan]Running Hydra for brute force attack...[/bold cyan]")
    for directory in login_directories:
        hydra_command = f"hydra -L {ROCKYOU_WORDLIST} -P {ROCKYOU_WORDLIST} {target_ip} {directory}"
        run_command(hydra_command, os.path.join(OUTPUT_DIR, 'hydra_results.txt'), f"Hydra - {directory}")
        apply_stealth()
    console.print("[bold green]Hydra brute force completed.[/bold green]")

def extract_sql_injection_candidates(nmap_output: str) -> list:
    candidates = []
    lines = nmap_output.splitlines()
    for line in lines:
        if 'http' in line and re.search(r"(\?|\&)id=|(\?|\&)page=|(\?|\&)search=", line):
            url = line.split()[1]
            candidates.append(url)
    return candidates

def extract_js_files(nmap_output: str) -> list:
    js_files = []
    lines = nmap_output.splitlines()
    for line in lines:
        if 'http' in line:
            matches = re.findall(r'(?i)http[s]?://[^\s"]+\.js', line)
            js_files.extend(matches)
    return js_files

def extract_services(nmap_output: str) -> list:
    services = []
    lines = nmap_output.splitlines()
    for line in lines:
        if 'open' in line:
            match = re.search(r'(\S+)\s+(\S+)', line)
            if match:
                service, version = match.groups()
                services.append(f"{service} {version}")
    return services

def run_all(target_domain: str, target_ip: str) -> None:
    if not amass_subdomain_enumeration(target_domain):
        console.print("[bold yellow]Skipping Amass subdomain enumeration.[/bold yellow]")
    if not sublist3r_subdomain_enumeration(target_domain):
        console.print("[bold yellow]Skipping Sublist3r subdomain enumeration.[/bold yellow]")
    if not theharvester_osint(target_domain):
        console.print("[bold yellow]Skipping theHarvester OSINT gathering.[/bold yellow]")

    nmap_output = nmap_scan(target_ip)
    services = extract_services(nmap_output)

    http_services = [service for service in services if 'http' in service.lower()]
    directories = []
    if http_services:
        gobuster_output = gobuster_directory_scan(target_ip)
        directories = extract_directories_from_gobuster(gobuster_output)
        nikto_scan(target_ip)

        if any('wp-' in directory for directory in directories):
            wpscan_scan(target_ip)

        sql_injection_candidates = extract_sql_injection_candidates(nmap_output)
        if sql_injection_candidates:
            sqlmap_scan(target_ip, sql_injection_candidates)

        js_files = extract_js_files(nmap_output)
        if js_files:
            jsparser_scan(target_ip, js_files)

        ffuf_fuzzing(target_ip)

    searchsploit_scan(services, target_ip)

    smb_services = [service for service in services if 'smb' in service.lower() or 'netbios' in service.lower()]
    if smb_services:
        enum4linux_scan(target_ip)

    login_directories = [directory for directory in directories if 'login' in directory]
    if login_directories:
        hydra_brute_force(target_ip, login_directories)

    console.print("[bold green]All scans and enumerations completed.[/bold green]")

if __name__ == "__main__":
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    target_domain = "example.com"
    target_ip = "192.168.1.1"

    run_all(target_domain, target_ip)

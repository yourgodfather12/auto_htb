import subprocess
import os
import re
import requests
import logging
import configparser
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# Initialize rich console
console = Console()

# Configuration setup
CONFIG_FILE = "config.ini"
config = configparser.ConfigParser()

# Default wordlists
SECLISTS_DIR = "/usr/share/seclists"
ROCKYOU_WORDLIST = "/usr/share/wordlists/rockyou.txt"
DIRBUSTER_WORDLIST = f"{SECLISTS_DIR}/Discovery/Web-Content/directory-list-2.3-medium.txt"

# Create config file if it doesn't exist
if not os.path.isfile(CONFIG_FILE):
    config['DEFAULT'] = {
        'Wordlist': DIRBUSTER_WORDLIST,
        'PasswordList': ROCKYOU_WORDLIST,
        'OutputDirectory': 'results'
    }
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

config.read(CONFIG_FILE)
WORDLIST = config['DEFAULT']['Wordlist']
PASSWORD_LIST = config['DEFAULT']['PasswordList']
OUTPUT_DIR = config['DEFAULT']['OutputDirectory']

# Setup logging
os.makedirs(OUTPUT_DIR, exist_ok=True)
logging.basicConfig(filename=f'{OUTPUT_DIR}/tool.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

REQUIRED_TOOLS = ["amass", "sublist3r", "theHarvester", "nmap", "gobuster", "nikto", 
                  "wpscan", "sqlmap", "python3", "ffuf", "searchsploit", "enum4linux", "hydra"]

# Utility functions
def log_error(message):
    logger.error(message)
    console.print(f"[bold red]{message}[/bold red]")

def run_command(command, output_file, description):
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
            with open(f"{OUTPUT_DIR}/results.txt", "a") as result_file:
                result_file.write(f"## {description} ##\n")
                result_file.write(result.stdout)
                result_file.write("\n\n")
            progress.update(task, advance=100)
            if result.returncode != 0:
                log_error(f"Error running {description}: {result.stderr}")
            return result.stdout
    except Exception as e:
        log_error(f"Error running {description}: {e}")
        return ""

def check_tool_availability(tool):
    return subprocess.call(f"type {tool}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def install_tool(tool):
    try:
        console.print(f"[bold yellow]Installing {tool}...[/bold yellow]")
        subprocess.run(f"sudo apt-get install -y {tool}", shell=True, check=True)
        console.print(f"[bold green]{tool} installed successfully.[/bold green]")
    except subprocess.CalledProcessError as e:
        log_error(f"Error installing {tool}: {e}")
        console.print(f"[bold red]Error installing {tool}. Please install it manually.[/bold red]")
        exit(1)

def check_and_install_tools():
    for tool in REQUIRED_TOOLS:
        if not check_tool_availability(tool):
            install_tool(tool)
        else:
            console.print(f"[bold green]{tool} is already installed.[/bold green]")

def ensure_wordlists():
    if not os.path.exists(ROCKYOU_WORDLIST):
        console.print(f"[bold yellow]rockyou.txt not found. Please download it and place it in /usr/share/wordlists.[/bold yellow]")
        log_error(f"Missing wordlist: {ROCKYOU_WORDLIST}")
        exit(1)
    if not os.path.exists(DIRBUSTER_WORDLIST):
        console.print(f"[bold yellow]SecLists not found. Please download SecLists from https://github.com/danielmiessler/SecLists and place it in /usr/share/seclists.[/bold yellow]")
        log_error(f"Missing wordlist: {DIRBUSTER_WORDLIST}")
        exit(1)

def ensure_https(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "https://" + url
    return url

def search_cves(service_name, version):
    try:
        cve_search_url = f"https://cve.circl.lu/api/search/{service_name}/{version}"
        response = requests.get(cve_search_url)
        if response.status_code == 200:
            cves = response.json()
            if cves:
                return cves
    except Exception as e:
        log_error(f"Error searching CVEs for {service_name} {version}: {e}")
    return []

def metasploit_exploit(cve, target_ip):
    try:
        msfconsole_command = f"""
        use auxiliary/scanner/vulnerabilities/ghdb_cve_search
        set CVE {cve}
        set RHOSTS {target_ip}
        run
        """
        subprocess.run(['msfconsole', '-q', '-x', msfconsole_command])
    except Exception as e:
        log_error(f"Error running Metasploit for CVE {cve}: {e}")

def extract_info_from_nmap(nmap_output):
    service_versions = re.findall(r'(\d{1,5}/\w+)\s+open\s+([\w-]+)\s+([\w.-]+)', nmap_output)
    services = [f"{match[1]} {match[2]}" for match in service_versions]
    return services, service_versions

def extract_directories_from_gobuster(gobuster_output):
    directories = re.findall(r'/(.+?)\s+\(Status: 200\)', gobuster_output)
    return directories

def print_next_steps(services):
    console.print("\n[bold yellow]Next Steps:[/bold yellow]")
    console.print("[bold green]1.[/bold green] Review the Amass and Sublist3r results:")
    console.print(f"   - Amass File: {OUTPUT_DIR}/amass_results.txt")
    console.print(f"   - Sublist3r File: {OUTPUT_DIR}/sublist3r_results.txt")
    console.print("   - Look for subdomains that might be relevant to the target's network surface.")

    console.print("\n[bold green]2.[/bold green] Review the Nmap scan results:")
    console.print(f"   - File: {OUTPUT_DIR}/nmap_scan.txt")
    console.print("   - Look for open ports and services running on the target machine.")
    console.print("   - Note any service versions, which will be useful for finding exploits.")

    console.print("\n[bold green]3.[/bold green] Analyze Dirb results:")
    console.print(f"   - File: {OUTPUT_DIR}/gobuster_results.txt")
    console.print("   - Look for hidden directories and files that might contain sensitive information or vulnerabilities.")

    console.print("\n[bold green]4.[/bold green] Check the ffuf results:")
    console.print(f"   - File: {OUTPUT_DIR}/ffuf_results.json")
    console.print("   - Look for potential parameters and paths that could be used to exploit vulnerabilities.")

    console.print("\n[bold green]5.[/bold green] Analyze JSParser results:")
    console.print(f"   - File: {OUTPUT_DIR}/jsparser_results.txt")
    console.print("   - Look for endpoints and URLs that might indicate further areas to test.")

    console.print("\n[bold green]6.[/bold green] Check the SearchSploit results:")
    for service in services:
        console.print(f"   - File: {OUTPUT_DIR}/searchsploit_{service.strip()}.txt")
        console.print(f"   - Look for potential exploits related to the identified services.")

    console.print("\n[bold green]7.[/bold green] Based on Nmap and Gobuster results, research potential vulnerabilities manually if necessary:")
    console.print("   - Use resources like Exploit-DB, CVE Details, or GitHub to find more information on potential exploits.")
    console.print("   - Verify the applicability of each exploit to your target system.")

    console.print("\n[bold green]8.[/bold green] If applicable, use Metasploit for exploitation:")
    console.print("   - Start Metasploit: msfconsole")
    console.print("   - Search for the specific exploit: search <exploit_name>")
    console.print("   - Set the required options: set RHOSTS <target_ip> and set LHOST <your_ip>")
    console.print("   - Execute the exploit: run")

    console.print("\n[bold green]9.[/bold green] For post-exploitation, use LinPEAS to automate local enumeration on the target system:")
    console.print("   - Download LinPEAS: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS")
    console.print("   - Upload to the target machine and execute: ./linpeas.sh")

    console.print("\n[bold green]10.[/bold green] Manual checks and privilege escalation:")
    console.print("   - Look for sensitive files, user credentials, and escalate privileges.")
    console.print("   - Check for misconfigured sudo privileges: sudo -l")
    console.print("   - Use GTFOBins for privilege escalation techniques: https://gtfobins.github.io/")

    console.print("\n[bold green]11.[/bold green] Maintaining access:")
    console.print("   - Establish an SSH connection for stable access: ssh <username>@<target_ip>")

    console.print("\n[bold green]12.[/bold green] Covering tracks:")
    console.print("   - Clear command history and logs: history -c")

    console.print("\n[bold green]13.[/bold green] Reporting:")
    console.print("   - Document all findings, exploitation methods, and potential mitigations.")

# Individual Task Functions
def amass_subdomain_enumeration(target_domain):
    console.print("[bold cyan]Running Amass for subdomain enumeration...[/bold cyan]")
    amass_command = f"amass enum -d {target_domain} -o {OUTPUT_DIR}/amass_results.txt"
    run_command(amass_command, f"{OUTPUT_DIR}/amass_results.txt", "Amass Subdomain Enumeration")
    console.print("[bold green]Amass subdomain enumeration completed.[/bold green]")

def sublist3r_subdomain_enumeration(target_domain):
    console.print("[bold cyan]Running Sublist3r for subdomain enumeration...[/bold cyan]")
    sublist3r_command = f"sublist3r -d {target_domain} -o {OUTPUT_DIR}/sublist3r_results.txt"
    run_command(sublist3r_command, f"{OUTPUT_DIR}/sublist3r_results.txt", "Sublist3r Subdomain Enumeration")
    console.print("[bold green]Sublist3r subdomain enumeration completed.[/bold green]")

def theharvester_osint(target_domain):
    console.print("[bold cyan]Running theHarvester for OSINT gathering...[/bold cyan]")
    theharvester_command = f"theHarvester -d {target_domain} -l 500 -b all -f {OUTPUT_DIR}/theHarvester_results.html"
    run_command(theharvester_command, f"{OUTPUT_DIR}/theHarvester_results.html", "theHarvester OSINT Gathering")
    console.print("[bold green]theHarvester OSINT gathering completed.[/bold green]")

def nmap_scan(target_ip):
    console.print("[bold cyan]Running Nmap scan...[/bold cyan]")
    nmap_command = f"nmap -sC -sV -oA {OUTPUT_DIR}/initial_scan {target_ip}"
    nmap_output = run_command(nmap_command, f"{OUTPUT_DIR}/nmap_scan.txt", "Nmap Scan")
    console.print("[bold green]Nmap scan completed.[/bold green]")
    return extract_info_from_nmap(nmap_output)

def gobuster_directory_scan(target_ip):
    console.print("[bold cyan]Running Gobuster for directory and file brute-forcing...[/bold cyan]")
    gobuster_command = f"gobuster dir -u https://{target_ip} -w {WORDLIST} -o {OUTPUT_DIR}/gobuster_results.txt"
    gobuster_output = run_command(gobuster_command, f"{OUTPUT_DIR}/gobuster_results.txt", "Gobuster Directory Scan")
    console.print("[bold green]Gobuster scan completed.[/bold green]")
    return extract_directories_from_gobuster(gobuster_output)

def nikto_scan(target_ip):
    console.print("[bold cyan]Running Nikto for web server scanning...[/bold cyan]")
    nikto_command = f"nikto -h https://{target_ip} -output {OUTPUT_DIR}/nikto_results.txt"
    run_command(nikto_command, f"{OUTPUT_DIR}/nikto_results.txt", "Nikto Web Server Scan")
    console.print("[bold green]Nikto scan completed.[/bold green]")

def wpscan_scan(target_ip):
    console.print("[bold cyan]Running WPScan for WordPress vulnerability scanning...[/bold cyan]")
    wpscan_command = f"wpscan --url https://{target_ip} --output {OUTPUT_DIR}/wpscan_results.txt"
    run_command(wpscan_command, f"{OUTPUT_DIR}/wpscan_results.txt", "WPScan")
    console.print("[bold green]WPScan completed.[/bold green]")

def sqlmap_scan(target_ip, sql_injection_candidates):
    console.print("[bold cyan]Running SQLMap for SQL injection testing...[/bold cyan]")
    for candidate in sql_injection_candidates:
        sqlmap_command = f"sqlmap -u https://{target_ip}/{candidate} --batch --output-dir={OUTPUT_DIR}/sqlmap_results"
        run_command(sqlmap_command, f"{OUTPUT_DIR}/sqlmap_results_{candidate}.txt", f"SQLMap - {candidate}")
    console.print("[bold green]SQLMap scan completed.[/bold green]")

def jsparser_scan(target_ip, js_files):
    console.print("[bold cyan]Running JSParser for JavaScript endpoint discovery...[/bold cyan]")
    for js_file in js_files:
        jsparser_command = f"python3 JSParser.py -u https://{target_ip}/{js_file} -o {OUTPUT_DIR}/jsparser_results.txt"
        run_command(jsparser_command, f"{OUTPUT_DIR}/jsparser_results.txt", f"JSParser - {js_file}")
    console.print("[bold green]JSParser completed.[/bold green]")

def ffuf_fuzzing(target_ip):
    console.print("[bold cyan]Running ffuf for URL and parameter fuzzing...[/bold cyan]")
    ffuf_command = f"ffuf -u https://{target_ip}/FUZZ -w {WORDLIST} -o {OUTPUT_DIR}/ffuf_results.json"
    run_command(ffuf_command, f"{OUTPUT_DIR}/ffuf_results.json", "ffuf URL Fuzzing")
    console.print("[bold green]ffuf URL fuzzing completed.[/bold green]")

def searchsploit_scan(services, target_ip):
    console.print("[bold cyan]Running SearchSploit for exploit searches...[/bold cyan]")
    for service in services:
        service_name, version = service.split()
        searchsploit_command = f"searchsploit {service_name} {version}"
        searchsploit_output = run_command(searchsploit_command, f"{OUTPUT_DIR}/searchsploit_{service_name}_{version}.txt", f"SearchSploit - {service_name} {version}")
        
        cves = search_cves(service_name, version)
        if cves:
            with open(f"{OUTPUT_DIR}/cves_{service_name}_{version}.txt", "w") as f:
                for cve in cves:
                    f.write(f"CVE ID: {cve['id']}\n")
                    f.write(f"Summary: {cve['summary']}\n\n")
            console.print(f"[bold green]CVEs found for {service_name} {version}: {', '.join([cve['id'] for cve in cves])}[/bold green]")
            
            # Attempt to exploit the first found CVE using Metasploit
            first_cve = cves[0]['id']
            console.print(f"[bold cyan]Attempting to exploit CVE {first_cve} using Metasploit...[/bold cyan]")
            metasploit_exploit(first_cve, target_ip)
        else:
            console.print(f"[bold yellow]No CVEs found for {service_name} {version}[/bold yellow]")

def enum4linux_scan(target_ip):
    console.print("[bold cyan]Running Enum4linux for SMB enumeration...[/bold cyan]")
    enum4linux_command = f"enum4linux -a {target_ip} > {OUTPUT_DIR}/enum4linux_results.txt"
    run_command(enum4linux_command, f"{OUTPUT_DIR}/enum4linux_results.txt", "Enum4linux SMB Enumeration")
    console.print("[bold green]Enum4linux scan completed.[/bold green]")

def hydra_brute_force(target_ip, login_directories):
    console.print("[bold cyan]Running Hydra for brute-forcing login credentials...[/bold cyan]")
    for login_dir in login_directories:
        hydra_command = f"hydra -L {OUTPUT_DIR}/usernames.txt -P {PASSWORD_LIST} {target_ip} http-post-form \"/{login_dir}:username=^USER^&password=^PASS^:F=incorrect\" -o {OUTPUT_DIR}/hydra_results.txt"
        run_command(hydra_command, f"{OUTPUT_DIR}/hydra_results_{login_dir}.txt", f"Hydra - {login_dir}")
    console.print("[bold green]Hydra brute-forcing completed.[/bold green]")

def summarize_results():
    console.print("\n[bold yellow]Summary of Results:[/bold yellow]")
    console.print(f"[bold green]Results saved in:[/bold green] {OUTPUT_DIR}/results.txt")
    console.print(f"[bold green]Detailed individual outputs saved in:[/bold green] {OUTPUT_DIR}")

def get_target_details():
    target_domain = input("Enter the target domain: ").strip()
    target_ip = input("Enter the target IP address: ").strip()
    return target_domain, target_ip

def main():
    global OUTPUT_DIR
    target_domain, target_ip = get_target_details()
    OUTPUT_DIR = f"{OUTPUT_DIR}/{target_ip}"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    check_and_install_tools()
    ensure_wordlists()

    amass_subdomain_enumeration(target_domain)
    sublist3r_subdomain_enumeration(target_domain)
    theharvester_osint(target_domain)
    services, service_versions = nmap_scan(target_ip)

    http_services = [service for service in services if 'http' in service.lower()]
    if http_services:
        directories = gobuster_directory_scan(target_ip)
        nikto_scan(target_ip)
        
        if any('wp-' in directory for directory in directories):
            wpscan_scan(target_ip)
        
        sql_injection_candidates = [directory for directory in directories if re.search(r'\b(login|search|id)\b', directory)]
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

    print_next_steps(services)
    summarize_results()

    console.print(f"\n[bold green]Scanning and enumeration completed. Results saved in {OUTPUT_DIR}[/bold green]")

if __name__ == "__main__":
    main()

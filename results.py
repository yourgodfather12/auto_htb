import re
import requests
from config import log_error

def extract_info_from_nmap(nmap_output: str) -> tuple:
    service_versions = re.findall(r'(\d{1,5}/\w+)\s+open\s+([\w.-]+)\s+([\w.-]+)', nmap_output)
    services = [f"{match[1]} {match[2]}" for match in service_versions]
    return services, service_versions

def extract_directories_from_gobuster(gobuster_output: str) -> list:
    directories = re.findall(r'/(.+?)\s+\(Status: \d{3}\)', gobuster_output)
    return directories

def search_cves(service_name: str, version: str) -> list:
    try:
        cve_search_url = f"https://cve.circl.lu/api/search/{service_name}/{version}"
        response = requests.get(cve_search_url)
        response.raise_for_status()
        cves = response.json()
        return cves if cves else []
    except requests.RequestException as e:
        log_error(f"Error searching CVEs for {service_name} {version}: {e}")
        return []

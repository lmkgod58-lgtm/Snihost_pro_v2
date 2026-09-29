#!/usr/bin/env python3
"""
Certificate Transparency (CT) Log Scraper
SOUTH AFRICA EDITION
Queries crt.sh for SA-specific base domains
"""

import os
import requests
import json
import time
import re
from urllib.parse import quote
from colorama import Fore, Style, init

init(autoreset=True)

DOMAINS_DIR = os.path.expanduser("~/snihost_pro/domains")
os.makedirs(DOMAINS_DIR, exist_ok=True)

CRTSH_API = "https://crt.sh/?q={}&output=json"

# SA-specific base domains for CT discovery
# These are confirmed zero-rated bases that likely have many subdomains
SA_BASE_DOMAINS = [
    # Universities
    'ac.za', 'uj.ac.za', 'ukzn.ac.za', 'unisa.ac.za', 'uct.ac.za',
    'wits.ac.za', 'up.ac.za', 'ufs.ac.za', 'uwc.ac.za', 'nwu.ac.za',
    'sun.ac.za', 'ru.ac.za', 'mandela.ac.za', 'tut.ac.za', 'vut.ac.za',
    'unizulu.ac.za', 'ul.ac.za', 'wsu.ac.za', 'dut.ac.za', 'cput.ac.za',
    
    # Government
    'gov.za', 'health.gov.za', 'treasury.gov.za', 'homeaffairs.gov.za',
    'education.gov.za', 'dhet.gov.za', 'sars.gov.za',
    
    # Health
    'nicd.ac.za', 'sahpra.org.za', 'higherhealth.ac.za',
    
    # Education platforms
    'mindset.africa', 'khanacademy.org', 'oerafrica.org',
    
    # TVET
    'edu.za', 'cput.ac.za', 'cjc.edu.za', 'cut.ac.za', 'dut.ac.za',
    'ewc.edu.za', 'falsebayCollege.co.za', 'mopaniCollege.edu.za',
    'northlink.co.za', 'orbitCollege.co.za', 'sedcol.co.za',
    'thekwiniCollege.co.za', 'tnc.edu.za', 'umfoloziCollege.co.za',
    'westcoastCollege.co.za', 'westcol.co.za',
    
    # Schools
    'co.za',  # Broad but effective for school domains
    
    # PBOs
    'org.za', 'co.za',
]

def query_crtsh(domain, wildcard=True):
    if wildcard and not domain.startswith("%."):
        search_term = f"%.{domain}"
    else:
        search_term = domain
    
    url = CRTSH_API.format(quote(search_term))
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            try:
                data = response.json()
                return data if data else []
            except:
                return []
        return []
    except:
        return []

def extract_subdomains(cert_data):
    subdomains = set()
    for entry in cert_data:
        name_value = entry.get("name_value", "")
        if not name_value:
            continue
        domains = name_value.split("\n")
        for domain in domains:
            domain = domain.strip().lower()
            if domain.startswith("*."):
                domain = domain[2:]
            if not domain:
                continue
            if "." in domain and len(domain) > 3:
                domain = domain.rstrip(".")
                subdomains.add(domain)
    return subdomains

def get_subdomains(domain, wildcard=True, include_base=True):
    print(f"\n{Fore.CYAN}Querying crt.sh: {domain}{Style.RESET_ALL}")
    
    cert_data = query_crtsh(domain, wildcard=wildcard)
    
    if not cert_data:
        print(f"{Fore.RED}No data for {domain}{Style.RESET_ALL}")
        if include_base:
            return [domain]
        return []
    
    print(f"{Fore.GREEN}Found {len(cert_data)} certs{Style.RESET_ALL}")
    
    subdomains = extract_subdomains(cert_data)
    
    if include_base and domain not in subdomains:
        subdomains.add(domain)
    
    sorted_subs = sorted(subdomains)
    print(f"{Fore.GREEN}Extracted {len(sorted_subs)} unique subdomains{Style.RESET_ALL}")
    
    return sorted_subs

def batch_ct_scan(domains, delay=2):
    results = {}
    total = len(domains)
    
    print(f"\n{Fore.CYAN}=== SA CT Batch Scan ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Scanning {total} SA base domains{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Delay: {delay}s between queries{Style.RESET_ALL}\n")
    
    for i, domain in enumerate(domains, 1):
        print(f"{Fore.CYAN}[{i}/{total}] {domain}{Style.RESET_ALL}")
        subdomains = get_subdomains(domain, wildcard=True, include_base=True)
        results[domain] = subdomains
        if i < total:
            time.sleep(delay)
    
    total_found = sum(len(subs) for subs in results.values())
    print(f"\n{Fore.GREEN}Complete: {total} bases, {total_found} subdomains{Style.RESET_ALL}")
    
    return results

def save_ct_results(results, filename=None):
    if filename is None:
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f"sa_ct_subdomains_{timestamp}.txt"
    
    filepath = os.path.join(DOMAINS_DIR, filename)
    
    all_subdomains = set()
    for subs in results.values():
        all_subdomains.update(subs)
    
    sorted_subs = sorted(all_subdomains)
    
    with open(filepath, 'w') as f:
        f.write(f"# SA CT Log Subdomain Discovery\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Base domains: {len(results)}\n")
        f.write(f"# Total unique: {len(sorted_subs)}\n")
        f.write("-" * 50 + "\n")
        for sub in sorted_subs:
            f.write(f"{sub}\n")
    
    print(f"{Fore.GREEN}Saved {len(sorted_subs)} to: {filepath}{Style.RESET_ALL}")
    return filepath

def preview_subdomains(subdomains, max_preview=20):
    print(f"\n{Fore.YELLOW}Preview ({min(max_preview, len(subdomains))} of {len(subdomains)}):{Style.RESET_ALL}")
    for sub in subdomains[:max_preview]:
        print(f"  → {sub}")
    if len(subdomains) > max_preview:
        print(f"  ... and {len(subdomains) - max_preview} more")

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SA CT Log Scraper{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Single domain")
    print("2. Batch scan (SA defaults)")
    print("3. Custom batch")
    
    choice = input("\nChoice (1-3): ").strip()
    
    if choice == '1':
        domain = input("Base domain: ").strip().lower()
        if not domain:
            print(f"{Fore.RED}No domain{Style.RESET_ALL}")
            return
        
        subdomains = get_subdomains(domain)
        preview_subdomains(subdomains)
        
        if subdomains:
            save = input("Save? (y/n): ").strip().lower()
            if save == 'y':
                results = {domain: subdomains}
                save_ct_results(results)
    
    elif choice == '2':
        print(f"{Fore.YELLOW}Scanning {len(SA_BASE_DOMAINS)} SA base domains...{Style.RESET_ALL}")
        results = batch_ct_scan(SA_BASE_DOMAINS, delay=3)
        
        for domain, subs in results.items():
            if len(subs) > 1:
                print(f"\n{Fore.GREEN}{domain}: {len(subs)} subdomains{Style.RESET_ALL}")
                preview_subdomains(subs, max_preview=5)
        
        save = input("\nSave all? (y/n): ").strip().lower()
        if save == 'y':
            save_ct_results(results)
    
    elif choice == '3':
        print("Enter base domains (one per line, empty to finish):")
        domains = []
        while True:
            line = input().strip().lower()
            if not line:
                break
            domains.append(line)
        
        if not domains:
            print(f"{Fore.RED}No domains{Style.RESET_ALL}")
            return
        
        results = batch_ct_scan(domains)
        
        for domain, subs in results.items():
            print(f"\n{Fore.GREEN}{domain}: {len(subs)} subdomains{Style.RESET_ALL}")
            preview_subdomains(subs, max_preview=5)
        
        save = input("\nSave all? (y/n): ").strip().lower()
        if save == 'y':
            save_ct_results(results)
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

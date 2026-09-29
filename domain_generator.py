#!/usr/bin/env python3
"""
Domain List Generator for SNI Host Finder PRO
Generates targeted domain lists by category
"""

import json
import os
import sys
from colorama import Fore, Style, init

init(autoreset=True)

DOMAINS_DIR = os.path.expanduser("~/snihost_pro/domains")

# Subdomain prefixes to try
SUBDOMAIN_PREFIXES = [
    'www', 'm', 'mobile', 'app', 'api', 'cdn', 'static', 'assets',
    'media', 'img', 'images', 'video', 'stream', 'download', 'dl',
    'mail', 'webmail', 'portal', 'login', 'auth', 'sso', 'secure',
    'dev', 'test', 'staging', 'beta', 'admin', 'panel', 'dashboard',
    'health', 'covid', 'vaccine', 'hospital', 'clinic', 'pharma',
    'edu', 'learn', 'student', 'campus', 'library', 'research',
    'news', 'blog', 'info', 'help', 'support', 'faq', 'docs',
    'gov', 'govt', 'ministry', 'department', 'service', 'public',
    'web', 'site', 'home', 'main', 'start', 'index', 'default'
]

# Country-specific government patterns
GOV_PATTERNS = {
    'nigeria': ['.gov.ng', '.gov.ng'],
    'kenya': ['.go.ke', '.or.ke', '.ac.ke'],
    'south_africa': ['.gov.za', '.ac.za', '.org.za'],
    'ghana': ['.gov.gh', '.edu.gh', '.org.gh'],
    'tanzania': ['.go.tz', '.ac.tz', '.or.tz'],
    'uganda': ['.go.ug', '.ac.ug', '.org.ug'],
    'global': ['.gov', '.int', '.org']
}

# Known zero-rated categories by region
ZERO_RATED_CATEGORIES = {
    'health': [
        'who.int', 'cdc.gov', 'nih.gov', 'nhs.uk', 'health.gov.au',
        'health.gov.ng', 'ncdc.gov.ng', 'nphcda.gov.ng',
        'health.go.ke', 'kmhfl.health.go.ke', 'healthportal.go.ke',
        'health.gov.za', 'sacoronavirus.co.za', 'nicd.ac.za',
        'health.gov.gh', 'ghs.gov.gh',
        'moh.go.tz', 'health.go.tz',
        'health.go.ug', 'moh.go.ug',
        'covid19.who.int', 'covid.cdc.gov', 'coronavirus.gov.uk',
        'vaccines.gov', 'myhealth.gov.ng', 'covid19.ncdc.gov.ng'
    ],
    'education': [
        'nuc.edu.ng', 'jamb.gov.ng', 'waecdirect.org', 'neco.gov.ng',
        'uonbi.ac.ke', 'strathmore.edu', 'ku.ac.ke', 'moi.ac.ke',
        'ukzn.ac.za', 'uct.ac.za', 'wits.ac.za', 'unisa.ac.za',
        'ug.edu.gh', 'knust.edu.gh', 'ucc.edu.gh',
        'udsm.ac.tz', 'sua.ac.tz',
        'makerere.ac.ug', 'kyu.ac.ug', 'muni.ac.ug',
        'khanacademy.org', 'coursera.org', 'edx.org', 'udemy.com',
        'unicef.org', 'unesco.org', 'worldbank.org'
    ],
    'social_media': [
        'web.whatsapp.com', 'm.facebook.com', 'facebook.com',
        'instagram.com', 'twitter.com', 'x.com', 'tiktok.com',
        'linkedin.com', 'snapchat.com', 'telegram.org',
        'messenger.com', 'fbcdn.net', 'instagram.f', 'twimg.com'
    ],
    'government': [
        'nigeria.gov.ng', 'kenya.go.ke', 'gov.za', 'ghana.gov.gh',
        'tanzania.go.tz', 'uganda.go.ug',
        'nass.gov.ng', 'njc.gov.ng', 'nnpcgroup.com',
        'treasury.go.ke', 'kra.go.ke', 'immigration.go.ke',
        'sars.gov.za', 'homeaffairs.gov.za', 'treasury.gov.za',
        'gra.gov.gh', 'ec.gov.gh',
        'tra.go.tz', 'immigration.go.tz',
        'ura.go.ug', 'ec.go.ug'
    ],
    'cdns_infrastructure': [
        'cdnjs.cloudflare.com', 'ajax.googleapis.com',
        'fonts.googleapis.com', 'bootstrapcdn.com',
        'unpkg.com', 'jsdelivr.net', 'cnd.jsdelivr.net',
        'akamai.net', 'akamaiedge.net', 'edgekey.net',
        'cloudfront.net', 'amazonaws.com',
        'fastly.net', 'fastlylb.net',
        'microsoft.com', 'windowsupdate.com', 'office.net',
        'googleusercontent.com', 'gstatic.com', 'googleapis.com'
    ]
}

def generate_with_subdomains(base_domains, prefixes=None, max_per_domain=5):
    """Generate subdomain variations"""
    if prefixes is None:
        prefixes = SUBDOMAIN_PREFIXES
    
    results = []
    for domain in base_domains:
        results.append(domain)  # Base domain
        for prefix in prefixes[:max_per_domain]:
            results.append(f"{prefix}.{domain}")
    return list(set(results))  # Remove duplicates

def generate_country_specific(country):
    """Generate domains for a specific country"""
    domains = []
    
    for tld in GOV_PATTERNS.get(country, GOV_PATTERNS['global']):
        domains.extend([
            f"health{tld}", f"education{tld}", f"finance{tld}",
            f"interior{tld}", f"defence{tld}", f"justice{tld}",
            f"agriculture{tld}", f"transport{tld}", f"energy{tld}",
            f"labour{tld}", f"trade{tld}", f"tourism{tld}",
        ])
    
    return generate_with_subdomains(domains, max_per_domain=3)

def generate_category_list(category, include_subdomains=True):
    """Generate full domain list for a category"""
    base = ZERO_RATED_CATEGORIES.get(category, [])
    if include_subdomains:
        return generate_with_subdomains(base, max_per_domain=5)
    return base

def save_domain_list(domains, filename, category='mixed'):
    """Save domain list to file"""
    os.makedirs(DOMAINS_DIR, exist_ok=True)
    filepath = os.path.join(DOMAINS_DIR, filename)
    
    with open(filepath, 'w') as f:
        f.write(f"# SNI Host Finder PRO - Domain List\n")
        f.write(f"# Category: {category}\n")
        f.write(f"# Total domains: {len(domains)}\n")
        f.write(f"# Generated: {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-" * 50 + "\n")
        for d in domains:
            f.write(f"{d}\n")
    
    print(f"{Fore.GREEN}Saved {len(domains)} domains to {filepath}{Style.RESET_ALL}")
    return filepath

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Domain List Generator{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    os.makedirs(DOMAINS_DIR, exist_ok=True)
    
    print("Select generation mode:")
    print("1. Generate by category (health, education, gov, social, cdn)")
    print("2. Generate by country (nigeria, kenya, south_africa, ghana, tanzania, uganda)")
    print("3. Generate all categories combined")
    print("4. Custom base domains + subdomains")
    
    choice = input("\nChoice (1-4): ").strip()
    
    if choice == '1':
        print("\nCategories: health, education, social_media, government, cdns_infrastructure")
        cat = input("Category: ").strip()
        domains = generate_category_list(cat)
        filename = f"{cat}_domains.txt"
        
    elif choice == '2':
        print("\nCountries: nigeria, kenya, south_africa, ghana, tanzania, uganda")
        country = input("Country: ").strip()
        domains = generate_country_specific(country)
        filename = f"{country}_domains.txt"
        
    elif choice == '3':
        all_domains = []
        for cat in ZERO_RATED_CATEGORIES:
            all_domains.extend(generate_category_list(cat, include_subdomains=False))
        domains = generate_with_subdomains(all_domains, max_per_domain=3)
        filename = "all_categories_domains.txt"
        
    elif choice == '4':
        print("Enter base domains (one per line, empty line to finish):")
        base = []
        while True:
            line = input().strip()
            if not line:
                break
            base.append(line)
        domains = generate_with_subdomains(base)
        filename = "custom_domains.txt"
        
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
        return
    
    save_domain_list(domains, filename, category=cat if choice == '1' else 'mixed')
    print(f"\n{Fore.YELLOW}Now run: python scanner.py {DOMAINS_DIR}/{filename}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

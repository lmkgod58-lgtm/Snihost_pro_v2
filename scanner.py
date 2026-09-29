#!/usr/bin/env python3
"""
SNI Host Finder PRO — Core Scanner
SOUTH AFRICA EDITION
Multi-threaded scanning with SA-specific heuristic scoring
"""

import socket
import ssl
import time
import csv
import json
import threading
import queue
import re
import dns.resolver
from colorama import Fore, Style, init
from tqdm import tqdm
import os
import sys

init(autoreset=True)

# ============ CONFIG ============
DEFAULT_THREADS = 200
DEFAULT_TIMEOUT = 5
RESULTS_DIR = os.path.expanduser("~/snihost_pro/results")
DOMAINS_DIR = os.path.expanduser("~/snihost_pro/domains")
PERSONAL_DB = os.path.expanduser("~/snihost_pro/my_zero_rated_hosts.json")

# SA CDN ranges (penalized by MTN/Vodacom per ICASA)
CDN_RANGES = {
    'cloudflare': ['104.16.0.0/12', '172.64.0.0/13', '103.21.244.0/22'],
    'aws': ['13.32.0.0/15', '52.84.0.0/15', '54.192.0.0/16'],
    'fastly': ['151.101.0.0/16', '157.52.64.0/18'],
    'akamai': ['23.32.0.0/11', '104.64.0.0/10'],
}

# SA Government/Education TLDs
SA_GOV_TLDS = ['.gov.za', '.go.za', '.org.za']
SA_EDU_TLDS = ['.ac.za', '.edu.za']

# SA ISP configs for scoring
SA_ISP_CONFIG = {
    'mtn': {'preferred_cats': ['government', 'education', 'health', 'job'], 'cdn_penalty': 15, 'static_bonus': 10},
    'vodacom': {'preferred_cats': ['government', 'education', 'health'], 'cdn_penalty': 15, 'static_bonus': 10},
    'telkom': {'preferred_cats': ['education', 'government', 'health'], 'cdn_penalty': 5, 'static_bonus': 5},
    'cell_c': {'preferred_cats': ['government', 'education', 'health'], 'cdn_penalty': 10, 'static_bonus': 8},
}

# ============ DIRTY HOST CLEANER ============

def clean_host_line(line):
    if not line or not isinstance(line, str):
        return None
    line = str(line).strip()
    if not line or line.startswith('#') or line.startswith('//'):
        return None
    line = re.sub(r'\s*[\(\[\{].*?[\)\]\}]\s*', '', line)
    line = re.sub(r'\s*[-|–—]\s*.*$', '', line)
    line = re.sub(r'\s*:\s*.*$', '', line)
    line = re.sub(r'^(https?://|http://|www\.)', '', line, flags=re.IGNORECASE)
    line = line.split('/')[0]
    line = re.sub(r':\d+$', '', line)
    line = re.sub(r'\s+', '', line)
    if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$', line):
        return None
    if '.' not in line:
        return None
    line = line.rstrip('.').lower()
    parts = line.split('.')
    if len(parts) < 2 or len(parts[-1]) < 2:
        return None
    return line

def clean_hosts_bulk(text_or_list):
    if isinstance(text_or_list, str):
        raw_lines = re.split(r'[\n\r,;|]+', text_or_list)
    elif isinstance(text_or_list, list):
        raw_lines = text_or_list
    else:
        return []
    clean_domains = []
    seen = set()
    for line in raw_lines:
        cleaned = clean_host_line(line)
        if cleaned and cleaned not in seen:
            clean_domains.append(cleaned)
            seen.add(cleaned)
    return clean_domains

# ============ SA-SPECIFIC UTILITIES ============

def ip_in_cidr(ip, cidr):
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
    except:
        return False

def detect_cdn(ip):
    for cdn_name, ranges in CDN_RANGES.items():
        for cidr in ranges:
            if ip_in_cidr(ip, cidr):
                return cdn_name
    return None

def is_static_ip(ip):
    for cdn_name, ranges in CDN_RANGES.items():
        for cidr in ranges:
            if ip_in_cidr(ip, cidr):
                return False
    return True

def get_sa_category(domain):
    d = domain.lower()
    if any(d.endswith(tld) for tld in SA_GOV_TLDS):
        return 'government', 35
    if any(d.endswith(tld) for tld in SA_EDU_TLDS):
        return 'education', 30
    if any(kw in d for kw in ['health', 'hospital', 'medical', 'covid', 'sahpra', 'nicd']):
        return 'health', 25
    if any(kw in d for kw in ['job', 'career', 'harambee', 'sayouth', 'employment']):
        return 'job', 20
    if any(kw in d for kw in ['facebook', 'whatsapp', 'instagram', 'twitter', 'x.com']):
        return 'social', 10
    if 'cdn' in d or 'cloud' in d:
        return 'cdn', 0
    return 'other', 0

# ============ PERSONAL DB ============

def load_personal_db():
    if os.path.exists(PERSONAL_DB):
        try:
            with open(PERSONAL_DB, 'r') as f:
                return json.load(f)
        except:
            return {'hosts': [], 'metadata': {'created': time.strftime('%Y-%m-%d')}}
    return {'hosts': [], 'metadata': {'created': time.strftime('%Y-%m-%d')}}

def is_in_personal_db(domain):
    db = load_personal_db()
    return any(h['domain'] == domain for h in db.get('hosts', []))

# ============ DNS & TLS ============

def resolve_dns(domain):
    results = {'ipv4': [], 'ipv6': [], 'error': None}
    try:
        answers = dns.resolver.resolve(domain, 'A')
        results['ipv4'] = [str(r) for r in answers]
    except Exception as e:
        results['error'] = str(e)
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        results['ipv6'] = [str(r) for r in answers]
    except:
        pass
    return results

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def check_tls_handshake(domain, timeout=5):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        start = time.time()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                elapsed = (time.time() - start) * 1000
                cipher = ssock.cipher()
                version = ssock.version()
                cert = ssock.getpeercert()
                cert_info = {
                    'subject': cert.get('subject'),
                    'issuer': cert.get('issuer'),
                    'not_after': cert.get('notAfter'),
                    'sans': cert.get('subjectAltName', []),
                    'serial': cert.get('serialNumber')
                }
                return True, version, cipher, cert_info, elapsed
    except Exception as e:
        return False, None, None, None, 0

def check_http_response(domain, timeout=5):
    import http.client
    try:
        conn = http.client.HTTPSConnection(domain, timeout=timeout)
        conn.request("HEAD", "/", headers={'Host': domain, 'User-Agent': 'Mozilla/5.0 (Linux; Android 10)'})
        resp = conn.getresponse()
        status = resp.status
        conn.close()
        return status, 'HTTPS', None
    except Exception as e:
        https_error = str(e)
    try:
        conn = http.client.HTTPConnection(domain, timeout=timeout)
        conn.request("HEAD", "/", headers={'Host': domain})
        resp = conn.getresponse()
        status = resp.status
        conn.close()
        return status, 'HTTP', None
    except Exception as e:
        return None, None, f"HTTPS: {https_error}, HTTP: {str(e)}"

# ============ SA-SPECIFIC SCORING ============

def calculate_sa_score(domain, tls_result, http_result, dns_result, cdn_name, isp=''):
    score = 0
    reasons = []
    
    # Personal DB bonus
    if is_in_personal_db(domain):
        score += 50
        reasons.append("IN PERSONAL DB (+50)")
    
    # SA Category
    category, cat_score = get_sa_category(domain)
    score += cat_score
    if cat_score > 0:
        reasons.append(f"SA {category} domain (+{cat_score})")
    
    # ISP-specific adjustments
    isp_config = SA_ISP_CONFIG.get(isp.lower()) if isp else None
    
    # TLS success
    if tls_result[0]:
        score += 15
        reasons.append("TLS OK (+15)")
        
        version = tls_result[1]
        if version == 'TLSv1.3':
            score += 5
        elif version == 'TLSv1.2':
            score += 3
        
        if tls_result[4] < 100:
            score += 5
            reasons.append("Fast (+5)")
        
        cert_info = tls_result[3]
        if cert_info:
            sans = cert_info.get('sans', [])
            if sans:
                score += 5
            
            issuer = str(cert_info.get('issuer', ''))
            if 'Let\'s Encrypt' in issuer:
                score += 0  # Neutral for SA
            elif any(ca in issuer for ca in ['DigiCert', 'GlobalSign', 'Sectigo', 'GeoTrust']):
                score += 5
                reasons.append("Commercial CA (+5)")
    
    # HTTP status
    if http_result[0]:
        status = http_result[0]
        if status == 200:
            score += 10
            reasons.append("HTTP 200 (+10)")
        elif status in (301, 302):
            score += 5
    
    # DNS / IP analysis
    if dns_result['ipv4']:
        score += 5
        ip = dns_result['ipv4'][0]
        
        # Static IP bonus (SA ISPs prefer static per ICASA)
        if is_static_ip(ip):
            bonus = isp_config.get('static_bonus', 5) if isp_config else 5
            score += bonus
            reasons.append(f"Static IP (+{bonus})")
        else:
            # CDN penalty
            if isp_config:
                penalty = isp_config.get('cdn_penalty', 5)
                score -= penalty
                reasons.append(f"CDN IP (-{penalty})")
        
        if len(dns_result['ipv4']) == 1:
            score += 3
            reasons.append("Single IP (+3)")
    
    # CDN bonus (only for Telkom)
    if cdn_name:
        if isp and isp.lower() == 'telkom':
            score += 5
            reasons.append(f"CDN: {cdn_name} (+5, Telkom OK)")
    
    score = min(score, 100)
    return score, reasons, category

# ============ SCANNER CLASS ============

class SNIProScanner:
    def __init__(self, threads=200, timeout=5, isp=''):
        self.threads = threads
        self.timeout = timeout
        self.isp = isp
        self.results = []
        self.lock = threading.Lock()
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.total = 0
        self.done = 0
        
    def worker(self):
        while not self.stop_event.is_set():
            try:
                domain = self.queue.get(timeout=1)
            except queue.Empty:
                continue
            
            if domain is None:
                break
            
            if not domain or domain.startswith('#'):
                with self.lock:
                    self.done += 1
                self.queue.task_done()
                continue
            
            domain = domain.strip().lower()
            
            try:
                dns_result = resolve_dns(domain)
                tls_result = check_tls_handshake(domain, self.timeout)
                http_result = (None, None, None)
                if tls_result[0]:
                    http_result = check_http_response(domain, self.timeout)
                
                cdn_name = None
                if dns_result['ipv4']:
                    cdn_name = detect_cdn(dns_result['ipv4'][0])
                
                reverse = None
                if dns_result['ipv4']:
                    reverse = reverse_dns(dns_result['ipv4'][0])
                
                score, reasons, category = calculate_sa_score(
                    domain, tls_result, http_result, dns_result, cdn_name, self.isp
                )
                
                result = {
                    'domain': domain,
                    'score': score,
                    'category': category,
                    'reasons': reasons,
                    'tls_success': tls_result[0],
                    'tls_version': tls_result[1],
                    'tls_time_ms': round(tls_result[4], 2),
                    'http_status': http_result[0],
                    'http_protocol': http_result[1],
                    'ipv4': dns_result['ipv4'],
                    'ipv6': dns_result['ipv6'],
                    'reverse_dns': reverse,
                    'cdn': cdn_name,
                    'is_static': dns_result['ipv4'] and is_static_ip(dns_result['ipv4'][0]),
                    'error': dns_result['error'] or http_result[2],
                    'in_personal_db': is_in_personal_db(domain)
                }
                
                if score >= 25:
                    with self.lock:
                        self.results.append(result)
                
                with self.lock:
                    self.done += 1
                    
            except Exception as e:
                with self.lock:
                    self.done += 1
            
            self.queue.task_done()
    
    def scan(self, domains, output_prefix='sa_scan'):
        self.total = len(domains)
        self.done = 0
        self.results = []
        
        os.makedirs(RESULTS_DIR, exist_ok=True)
        
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        txt_file = os.path.join(RESULTS_DIR, f'{output_prefix}_{timestamp}.txt')
        csv_file = os.path.join(RESULTS_DIR, f'{output_prefix}_{timestamp}.csv')
        json_file = os.path.join(RESULTS_DIR, f'{output_prefix}_{timestamp}.json')
        
        for d in domains:
            self.queue.put(d)
        
        threads = []
        for _ in range(min(self.threads, len(domains))):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        print(f"\n{Fore.CYAN}=== SA Scanner ==={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Domains: {self.total} | Threads: {self.threads} | ISP: {self.isp or 'Any'}{Style.RESET_ALL}\n")
        
        pbar = tqdm(total=self.total, desc="Scanning", unit="domains")
        while self.done < self.total:
            time.sleep(0.5)
            pbar.n = self.done
            pbar.refresh()
        pbar.close()
        
        self.queue.join()
        self.stop_event.set()
        for _ in threads:
            self.queue.put(None)
        for t in threads:
            t.join(timeout=2)
        
        self.results.sort(key=lambda x: x['score'], reverse=True)
        self._save_results(txt_file, csv_file, json_file)
        self._print_summary()
        
        return self.results
    
    def _save_results(self, txt_file, csv_file, json_file):
        with open(txt_file, 'w') as f:
            f.write(f"# SA Scanner Results\n")
            f.write(f"# ISP: {self.isp or 'Any'}\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {self.total}\n")
            f.write(f"# Found: {len(self.results)}\n")
            f.write("-" * 60 + "\n")
            for r in self.results:
                status = r['http_status'] if r['http_status'] else 'TLS_ONLY'
                static = " [STATIC]" if r.get('is_static') else ""
                db = " [DB]" if r.get('in_personal_db') else ""
                f.write(f"{r['domain']} (Status: {status}, Score: {r['score']}, Cat: {r['category']}){static}{db}\n")
        
        if self.results:
            keys = ['domain', 'score', 'category', 'tls_success', 'tls_version', 
                    'tls_time_ms', 'http_status', 'http_protocol', 'ipv4', 'ipv6',
                    'reverse_dns', 'cdn', 'is_static', 'reasons', 'error', 'in_personal_db']
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for r in self.results:
                    row = {k: r.get(k, '') for k in keys}
                    row['reasons'] = ' | '.join(r.get('reasons', []))
                    row['ipv4'] = ', '.join(r.get('ipv4', []))
                    row['ipv6'] = ', '.join(r.get('ipv6', []))
                    writer.writerow(row)
        
        with open(json_file, 'w') as f:
            json.dump({
                'metadata': {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'total_scanned': self.total,
                    'found': len(self.results),
                    'threads': self.threads,
                    'isp': self.isp
                },
                'results': self.results
            }, f, indent=2, default=str)
        
        print(f"\n{Fore.GREEN}Saved to:{Style.RESET_ALL}")
        print(f"  TXT:  {txt_file}")
        print(f"  CSV:  {csv_file}")
        print(f"  JSON: {json_file}")
    
    def _print_summary(self):
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SCAN COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"Total: {self.total}")
        print(f"Found: {len(self.results)}")
        
        if self.results:
            print(f"\n{Fore.YELLOW}Top 10:{Style.RESET_ALL}")
            for i, r in enumerate(self.results[:10], 1):
                color = Fore.GREEN if r['score'] >= 70 else Fore.YELLOW if r['score'] >= 50 else Fore.RED
                db = f" {Fore.MAGENTA}[DB]{Style.RESET_ALL}" if r.get('in_personal_db') else ""
                static = f" {Fore.CYAN}[STATIC]{Style.RESET_ALL}" if r.get('is_static') else ""
                print(f"  {i}. {color}{r['domain']}{Style.RESET_ALL}{db}{static} ({r['score']}, {r['category']})")
        
        categories = {}
        for r in self.results:
            cat = r['category']
            categories[cat] = categories.get(cat, 0) + 1
        if categories:
            print(f"\n{Fore.YELLOW}By Category:{Style.RESET_ALL}")
            for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
                print(f"  {cat}: {count}")

# ============ MAIN ============

def load_domains(filepath):
    domains = []
    if not os.path.exists(filepath):
        print(f"{Fore.RED}File not found: {filepath}{Style.RESET_ALL}")
        return domains
    
    ext = os.path.splitext(filepath)[1].lower()
    if ext == '.txt':
        with open(filepath, 'r') as f:
            raw = f.read()
            domains = clean_hosts_bulk(raw)
    elif ext == '.json':
        with open(filepath, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        domains.extend(clean_hosts_bulk([item.get('domain', '')]))
                    elif isinstance(item, str):
                        domains.extend(clean_hosts_bulk([item]))
            elif isinstance(data, dict) and 'domains' in data:
                domains = clean_hosts_bulk(data['domains'])
    
    return domains

def paste_dirty_hosts():
    print(f"\n{Fore.CYAN}=== Paste Dirty Hosts ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Paste hosts (descriptions auto-removed){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Type DONE when finished:{Style.RESET_ALL}\n")
    
    lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == 'DONE':
                break
            lines.append(line)
        except EOFError:
            break
    
    raw = '\n'.join(lines)
    clean = clean_hosts_bulk(raw)
    
    print(f"\n{Fore.GREEN}Cleaned {len(clean)} hosts:{Style.RESET_ALL}")
    for d in clean:
        print(f"  ✓ {d}")
    
    if clean:
        filename = f"sa_pasted_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(DOMAINS_DIR, filename)
        os.makedirs(DOMAINS_DIR, exist_ok=True)
        with open(filepath, 'w') as f:
            for d in clean:
                f.write(f"{d}\n")
        print(f"\n{Fore.GREEN}Saved to: {filepath}{Style.RESET_ALL}")
        return filepath, clean
    
    return None, clean

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SA Scanner v2.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(DOMAINS_DIR, exist_ok=True)
    
    db_count = len(load_personal_db().get('hosts', []))
    print(f"{Fore.GREEN}Personal DB: {db_count} hosts{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Scan from file")
    print("2. Paste dirty hosts")
    print("3. Quick scan (SA defaults)")
    
    choice = input("\nChoice (1-3): ").strip()
    
    isp = input("Your ISP (MTN/Vodacom/Telkom/Cell C): ").strip()
    
    domains = []
    
    if choice == '1':
        files = [f for f in os.listdir(DOMAINS_DIR) if f.endswith(('.txt', '.json'))]
        if files:
            for i, f in enumerate(files, 1):
                print(f"  {i}. {f}")
            fc = input("\nFile number or path: ").strip()
            if fc.isdigit() and 1 <= int(fc) <= len(files):
                domain_file = os.path.join(DOMAINS_DIR, files[int(fc)-1])
            else:
                domain_file = os.path.join(DOMAINS_DIR, fc) if not os.path.isabs(fc) else fc
        else:
            domain_file = input("Full path: ").strip()
        
        domains = load_domains(domain_file)
        
    elif choice == '2':
        _, domains = paste_dirty_hosts()
        
    elif choice == '3':
        domains = [
            'www.uj.ac.za', 'www.ukzn.ac.za', 'www.unisa.ac.za',
            'www.health.gov.za', 'sacoronavirus.co.za',
            'everythingmaths.co.za', 'learn.mindset.africa'
        ]
        
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
        return
    
    if not domains:
        print(f"{Fore.RED}No valid domains{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}Loaded {len(domains)} clean domains{Style.RESET_ALL}")
    
    try:
        threads = int(input(f"Threads (default {DEFAULT_THREADS}): ") or DEFAULT_THREADS)
    except:
        threads = DEFAULT_THREADS
    
    try:
        timeout = int(input(f"Timeout (default {DEFAULT_TIMEOUT}): ") or DEFAULT_TIMEOUT)
    except:
        timeout = DEFAULT_TIMEOUT
    
    scanner = SNIProScanner(threads=threads, timeout=timeout, isp=isp)
    scanner.scan(domains)
    
    print(f"\n{Fore.GREEN}Done!{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

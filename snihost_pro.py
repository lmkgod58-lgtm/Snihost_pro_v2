#!/usr/bin/env python3
"""
SNI Host Finder PRO — Unified Scanner
Integrates ALL modules into one automated workflow:
CT Scraper → TLS Tests → ML Scoring → ISP Rules → Community → DPI → Ranked Output
"""

import os
import sys
import time
import json
import socket

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import Fore, Style, init
from ct_scraper import get_subdomains
from advanced_tls import run_all_advanced_tests
from ml_scorer import SNIPredictor, extract_features
from isp_inference import ISPRuleMiner
from community_intel import IntelQuery, CommunityDatabase

init(autoreset=True)

# ============ CONFIG ============

RESULTS_DIR = os.path.expanduser("~/snihost_pro/results")
DOMAINS_DIR = os.path.expanduser("~/snihost_pro/domains")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(DOMAINS_DIR, exist_ok=True)

# ============ UNIFIED WORKFLOW ============

class UnifiedScanner:
    """
    Master scanner that orchestrates all modules
    """
    
    def __init__(self, isp='', country='', threads=100, timeout=5):
        self.isp = isp
        self.country = country
        self.threads = threads
        self.timeout = timeout
        
        # Initialize all modules
        self.ml_predictor = SNIPredictor()
        self.community_query = IntelQuery()
        self.community_db = CommunityDatabase()
        
        # Load ISP rules if available
        self.isp_miner = None
        if isp and country:
            rules_file = os.path.expanduser(f"~/snihost_pro/isp_rules/latest_{isp.lower()}_{country.lower()}.json")
            if os.path.exists(rules_file):
                self.isp_miner = ISPRuleMiner(isp, country)
                with open(rules_file, 'r') as f:
                    data = json.load(f)
                    self.isp_miner.rules = data.get('rules', [])
        
        self.results = []
    
    def discover_domains(self, base_domains, use_ct=True):
        """
        Step 1: Domain Discovery
        Use CT logs + base domains
        """
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  STEP 1: Domain Discovery{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        all_domains = set()
        
        # Add base domains
        for d in base_domains:
            all_domains.add(d.lower().strip())
        
        # CT log discovery
        if use_ct:
            print(f"\n{Fore.YELLOW}Querying Certificate Transparency logs...{Style.RESET_ALL}")
            for base in base_domains:
                try:
                    subs = get_subdomains(base, wildcard=True, include_base=False)
                    print(f"  {base}: {len(subs)} subdomains found")
                    all_domains.update(subs)
                    time.sleep(2)  # Be nice to crt.sh
                except Exception as e:
                    print(f"  {Fore.RED}Error scanning {base}: {e}{Style.RESET_ALL}")
        
        domains = sorted(all_domains)
        print(f"\n{Fore.GREEN}Total unique domains: {len(domains)}{Style.RESET_ALL}")
        
        return domains
    
    def prefilter_domains(self, domains):
        """
        Step 2: Quick Pre-filter
        Basic connectivity check — remove dead hosts fast
        """
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  STEP 2: Quick Pre-filter{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        alive = []
        total = len(domains)
        
        for i, domain in enumerate(domains, 1):
            try:
                socket.gethostbyname(domain)
                alive.append(domain)
            except:
                pass
            
            if i % 50 == 0:
                print(f"  Checked {i}/{total}... {len(alive)} alive")
        
        print(f"\n{Fore.GREEN}{len(alive)}/{total} domains responsive{Style.RESET_ALL}")
        return alive
    
    def deep_scan(self, domains):
        """
        Step 3: Deep Scan + Scoring
        Run TLS tests, ML scoring, ISP rules, community intel
        """
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  STEP 3: Deep Analysis{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        scored_results = []
        
        for i, domain in enumerate(domains, 1):
            print(f"\n{Fore.YELLOW}[{i}/{len(domains)}] Analyzing: {domain}{Style.RESET_ALL}")
            
            try:
                # Run advanced TLS tests
                tls_results = run_all_advanced_tests(domain, self.timeout)
                
                # Build scan result for scoring
                scan_result = {
                    'domain': domain,
                    'category': self._guess_category(domain),
                    'tls_success': tls_results['tests']['empty_sni'].get('accepts_empty_sni') or 
                                  tls_results['tests']['wrong_sni'].get('accepts_wrong_sni'),
                    'tls_version': tls_results['tests']['tls_versions'].get('oldest_supported'),
                    'http_status': 200 if tls_results['exploitability_score'] > 30 else None,
                    'tls_time_ms': tls_results['tests']['empty_sni'].get('response_time_ms', 9999),
                    'cdn': None,  # Would need IP lookup
                    'ipv4': [],
                    'reverse_dns': None,
                    'in_personal_db': False,
                    'score': tls_results['exploitability_score']
                }
                
                # ML Prediction
                ml_pred = self.ml_predictor.predict(scan_result)
                ml_score = ml_pred['predicted_probability']
                
                # ISP Rule Prediction
                isp_score = 0
                if self.isp_miner:
                    isp_pred = self.isp_miner.predict_host(domain)
                    if isp_pred.get('predictable'):
                        isp_score = isp_pred.get('confidence', 0)
                
                # Community Intel
                comm_intel = self.community_query.check_host(domain, self.isp, self.country)
                comm_score = 0
                if comm_intel.get('known'):
                    comm_score = comm_intel.get('success_rate', 0)
                    if comm_intel.get('recent_working'):
                        comm_score += 20
                
                # Combined Score (weighted)
                combined_score = (
                    tls_results['exploitability_score'] * 0.3 +      # 30% TLS
                    ml_score * 0.25 +                                 # 25% ML
                    isp_score * 0.25 +                                # 25% ISP Rules
                    min(comm_score, 100) * 0.2                        # 20% Community
                )
                
                final_result = {
                    'domain': domain,
                    'tls_results': tls_results,
                    'ml_score': ml_score,
                    'isp_score': isp_score,
                    'comm_score': min(comm_score, 100),
                    'combined_score': round(combined_score, 1),
                    'exploitability': tls_results['exploitability_score'],
                    'recommendation': self._get_recommendation(combined_score)
                }
                
                scored_results.append(final_result)
                
                print(f"  TLS: {tls_results['exploitability_score']}% | "
                      f"ML: {ml_score}% | ISP: {isp_score}% | Comm: {comm_score}%")
                print(f"  {Fore.GREEN}COMBINED: {combined_score:.1f}% — {final_result['recommendation']}{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")
            
            time.sleep(0.5)  # Rate limiting
        
        # Sort by combined score
        scored_results.sort(key=lambda x: x['combined_score'], reverse=True)
        
        return scored_results
    
    def _guess_category(self, domain):
        """Guess domain category from name"""
        d = domain.lower()
        if any(t in d for t in ['.gov', '.go.']):
            return 'government'
        elif any(t in d for t in ['.ac.', '.edu']):
            return 'education'
        elif any(t in d for t in ['health', 'hospital', 'medical', 'covid']):
            return 'health'
        elif any(t in d for t in ['facebook', 'whatsapp', 'instagram', 'twitter']):
            return 'social'
        elif any(t in d for t in ['cdn', 'cloud', 'static']):
            return 'cdn'
        return 'other'
    
    def _get_recommendation(self, score):
        """Get recommendation text"""
        if score >= 70:
            return f"{Fore.GREEN}HIGH PRIORITY — Test first!{Style.RESET_ALL}"
        elif score >= 50:
            return f"{Fore.YELLOW}MEDIUM PRIORITY — Likely works{Style.RESET_ALL}"
        elif score >= 30:
            return f"{Fore.YELLOW}LOW PRIORITY — Maybe{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}SKIP — Unlikely to work{Style.RESET_ALL}"
    
    def save_results(self, results, filename_prefix='unified'):
        """Save comprehensive results"""
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        # JSON full results
        json_file = os.path.join(RESULTS_DIR, f'{filename_prefix}_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump({
                'metadata': {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'isp': self.isp,
                    'country': self.country,
                    'total_scanned': len(results)
                },
                'results': results
            }, f, indent=2, default=str)
        
        # TXT clean output
        txt_file = os.path.join(RESULTS_DIR, f'{filename_prefix}_{timestamp}.txt')
        with open(txt_file, 'w') as f:
            f.write(f"# SNI Host Finder PRO — Unified Results\n")
            f.write(f"# ISP: {self.isp} | Country: {self.country}\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {len(results)}\n")
            f.write("-" * 70 + "\n")
            f.write(f"{'#':<4} {'Domain':<40} {'Score':<8} {'Rec':<20}\n")
            f.write("-" * 70 + "\n")
            
            for i, r in enumerate(results, 1):
                rec = "HIGH" if r['combined_score'] >= 70 else "MED" if r['combined_score'] >= 50 else "LOW" if r['combined_score'] >= 30 else "SKIP"
                f.write(f"{i:<4} {r['domain']:<40} {r['combined_score']:<8} {rec:<20}\n")
        
        # CSV
        csv_file = os.path.join(RESULTS_DIR, f'{filename_prefix}_{timestamp}.csv')
        import csv
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Rank', 'Domain', 'Combined Score', 'TLS Score', 
                           'ML Score', 'ISP Score', 'Community Score', 'Recommendation'])
            for i, r in enumerate(results, 1):
                rec = "HIGH" if r['combined_score'] >= 70 else "MED" if r['combined_score'] >= 50 else "LOW" if r['combined_score'] >= 30 else "SKIP"
                writer.writerow([i, r['domain'], r['combined_score'], r['exploitability'],
                               r['ml_score'], r['isp_score'], r['comm_score'], rec])
        
        print(f"\n{Fore.GREEN}Results saved:{Style.RESET_ALL}")
        print(f"  JSON: {json_file}")
        print(f"  TXT:  {txt_file}")
        print(f"  CSV:  {csv_file}")
        
        return txt_file
    
    def run(self, base_domains, use_ct=True, max_results=50):
        """
        Run full unified workflow
        """
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  SNI Host Finder PRO — Unified Scanner{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"  ISP: {self.isp or 'Not specified'}")
        print(f"  Country: {self.country or 'Not specified'}")
        print(f"  Base domains: {len(base_domains)}")
        print(f"  CT discovery: {'Enabled' if use_ct else 'Disabled'}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Step 1: Discover
        domains = self.discover_domains(base_domains, use_ct)
        
        # Step 2: Pre-filter
        alive = self.prefilter_domains(domains)
        
        # Limit for deep scan
        if len(alive) > max_results * 3:
            print(f"\n{Fore.YELLOW}Limiting to top {max_results * 3} for deep scan{Style.RESET_ALL}")
            alive = alive[:max_results * 3]
        
        # Step 3: Deep scan
        results = self.deep_scan(alive)
        
        # Step 4: Save
        if results:
            self.save_results(results[:max_results])
            
            # Print top 10
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}  TOP 10 CANDIDATES{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            
            for i, r in enumerate(results[:10], 1):
                color = Fore.GREEN if r['combined_score'] >= 70 else Fore.YELLOW if r['combined_score'] >= 50 else Fore.RED
                print(f"\n  {i}. {color}{r['domain']}{Style.RESET_ALL}")
                print(f"     Combined: {color}{r['combined_score']}%{Style.RESET_ALL}")
                print(f"     TLS: {r['exploitability']}% | ML: {r['ml_score']}% | ISP: {r['isp_score']}% | Comm: {r['comm_score']}%")
        else:
            print(f"\n{Fore.RED}No results generated{Style.RESET_ALL}")

# ============ MAIN ============

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SNI Host Finder PRO v3.0{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Unified Scanner — All Modules Integrated{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Full unified scan (CT + TLS + ML + ISP + Community)")
    print("2. Quick scan (base domains only, no CT)")
    print("3. Scan from file")
    print("4. Paste dirty hosts")
    
    choice = input("\nChoice (1-4): ").strip()
    
    isp = input("Your ISP (optional): ").strip()
    country = input("Your Country (optional): ").strip()
    
    base_domains = []
    
    if choice == '1':
        print(f"\n{Fore.YELLOW}Enter base domains for CT discovery (one per line, empty to finish):{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: gov.ng, go.ke, health.gov.ng{Style.RESET_ALL}")
        while True:
            line = input().strip().lower()
            if not line:
                break
            base_domains.append(line)
        
        if not base_domains:
            # Default
            base_domains = ['gov.ng', 'go.ke', 'gov.za', 'health.gov.ng', 'who.int']
            print(f"{Fore.YELLOW}Using defaults: {', '.join(base_domains)}{Style.RESET_ALL}")
        
        scanner = UnifiedScanner(isp=isp, country=country)
        scanner.run(base_domains, use_ct=True)
    
    elif choice == '2':
        print(f"\n{Fore.YELLOW}Enter domains to scan (one per line, empty to finish):{Style.RESET_ALL}")
        while True:
            line = input().strip().lower()
            if not line:
                break
            base_domains.append(line)
        
        if not base_domains:
            print(f"{Fore.RED}No domains entered{Style.RESET_ALL}")
            return
        
        scanner = UnifiedScanner(isp=isp, country=country)
        scanner.run(base_domains, use_ct=False)
    
    elif choice == '3':
        filepath = input("Path to domain file: ").strip()
        if not os.path.exists(filepath):
            print(f"{Fore.RED}File not found: {filepath}{Style.RESET_ALL}")
            return
        
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    base_domains.append(line.lower())
        
        scanner = UnifiedScanner(isp=isp, country=country)
        scanner.run(base_domains, use_ct=False)
    
    elif choice == '4':
        print(f"\n{Fore.YELLOW}Paste dirty hosts (type DONE when finished):{Style.RESET_ALL}")
        lines = []
        while True:
            line = input()
            if line.strip().upper() == 'DONE':
                break
            lines.append(line)
        
        # Import cleaner from scanner
        from scanner import clean_hosts_bulk
        base_domains = clean_hosts_bulk('\n'.join(lines))
        
        print(f"{Fore.GREEN}Cleaned {len(base_domains)} domains{Style.RESET_ALL}")
        
        scanner = UnifiedScanner(isp=isp, country=country)
        scanner.run(base_domains, use_ct=False)
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

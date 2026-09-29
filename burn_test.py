#!/usr/bin/env python3
"""
Data Burn Test Helper
Tests if a candidate SNI host actually gives free data
"""

import os
import time
import json
from colorama import Fore, Style, init

init(autoreset=True)

RESULTS_DIR = os.path.expanduser("~/snihost_pro/results")
BURN_LOG = os.path.expanduser("~/snihost_pro/burn_test_log.json")

def load_scan_results():
    """Load the most recent scan results"""
    files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.json')]
    if not files:
        print(f"{Fore.RED}No scan results found. Run scanner.py first.{Style.RESET_ALL}")
        return None
    
    files.sort(reverse=True)
    latest = os.path.join(RESULTS_DIR, files[0])
    
    with open(latest, 'r') as f:
        return json.load(f)

def get_high_confidence_hosts(min_score=50, max_hosts=20):
    """Get top candidates for burn testing"""
    data = load_scan_results()
    if not data:
        return []
    
    results = data.get('results', [])
    filtered = [r for r in results if r.get('score', 0) >= min_score]
    filtered.sort(key=lambda x: x.get('score', 0), reverse=True)
    
    return filtered[:max_hosts]

def generate_vpn_config(domain, vpn_type='tls_tunnel'):
    """Generate config string for VPN app"""
    if vpn_type == 'tls_tunnel':
        config = f"""
=== TLS Tunnel Config ===
SNI/SSL: {domain}
Server: [Your VPN server IP]
Port: 443
Payload: [Your payload if needed]

=== How to Test ===
1. Open TLS Tunnel
2. Set SNI Host to: {domain}
3. Connect VPN
4. Browse heavily for 3-5 minutes
5. Check if your data balance changed
"""
    elif vpn_type == 'ha_tunnel':
        config = f"""
=== HA Tunnel Plus Config ===
Custom SNI (SSL/TLS): {domain}
Server: [Your SSH server]
Port: 443

=== How to Test ===
1. Open HA Tunnel Plus
2. Go to Custom SNI mode
3. Enter SNI: {domain}
4. Connect
5. Browse heavily for 3-5 minutes
6. Check data balance
"""
    else:
        config = f"SNI Host: {domain}"
    
    return config

def log_burn_test(domain, worked, data_used, notes=''):
    """Log burn test result"""
    log_entry = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'domain': domain,
        'worked': worked,
        'data_used_mb': data_used,
        'notes': notes
    }
    
    log = []
    if os.path.exists(BURN_LOG):
        with open(BURN_LOG, 'r') as f:
            log = json.load(f)
    
    log.append(log_entry)
    
    with open(BURN_LOG, 'w') as f:
        json.dump(log, f, indent=2)
    
    print(f"{Fore.GREEN}Result logged to {BURN_LOG}{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Data Burn Test Helper{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    # Get candidates
    print(f"{Fore.YELLOW}Loading high-confidence candidates...{Style.RESET_ALL}")
    candidates = get_high_confidence_hosts(min_score=50, max_hosts=20)
    
    if not candidates:
        print(f"{Fore.RED}No candidates found. Run scanner.py first.{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.GREEN}Found {len(candidates)} candidates for burn testing:{Style.RESET_ALL}\n")
    
    for i, c in enumerate(candidates, 1):
        score_color = Fore.GREEN if c.get('score', 0) >= 70 else Fore.YELLOW
        print(f"  {i}. {score_color}{c.get('domain', 'unknown')}{Style.RESET_ALL} "
              f"(Score: {c.get('score', 0)}, Category: {c.get('category', 'unknown')})")
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}BURN TEST INSTRUCTIONS:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print("""
1. Note your EXACT data balance before starting
2. Pick a candidate from the list above
3. I'll generate the VPN config for you
4. Connect VPN with that SNI host
5. Browse heavily (YouTube, downloads) for 3-5 minutes
6. Disconnect VPN
7. Check your data balance again
8. Tell me if it worked!
""")
    
    while True:
        choice = input(f"\nEnter candidate number (or 'q' to quit): ").strip()
        if choice.lower() == 'q':
            break
        
        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(candidates):
                print(f"{Fore.RED}Invalid number{Style.RESET_ALL}")
                continue
            
            candidate = candidates[idx]
            domain = candidate.get('domain', '')
            
            print(f"\n{Fore.CYAN}Selected: {domain}{Style.RESET_ALL}")
            print(f"Confidence Score: {candidate.get('score', 0)}")
            print(f"Category: {candidate.get('category', 'unknown')}")
            print(f"HTTP Status: {candidate.get('http_status', 'N/A')}")
            print(f"TLS Version: {candidate.get('tls_version', 'N/A')}")
            print(f"CDN: {candidate.get('cdn', 'None')}")
            
            print(f"\n{Fore.YELLOW}VPN Config:{Style.RESET_ALL}")
            print(generate_vpn_config(domain, 'tls_tunnel'))
            print(generate_vpn_config(domain, 'ha_tunnel'))
            
            worked = input(f"\nDid it work? (y/n/skip): ").strip().lower()
            if worked == 'y':
                data_used = input("Approximate data used (MB, 0 if none): ").strip()
                try:
                    data_used = float(data_used)
                except:
                    data_used = 0
                log_burn_test(domain, True, data_used, "Working SNI host!")
                print(f"{Fore.GREEN}✓ Logged as WORKING!{Style.RESET_ALL}")
            elif worked == 'n':
                data_used = input("Approximate data used (MB): ").strip()
                try:
                    data_used = float(data_used)
                except:
                    data_used = 0
                log_burn_test(domain, False, data_used, "Did not work")
                print(f"{Fore.RED}✗ Logged as NOT WORKING{Style.RESET_ALL}")
            
        except ValueError:
            print(f"{Fore.RED}Enter a number or 'q'{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

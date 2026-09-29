#!/usr/bin/env python3
"""
ISP Rule Inference Module
Analyzes burn-test results to discover ISP zero-rating patterns
Uses pattern mining to predict which hosts will work
"""

import json
import os
import time
import re
from collections import defaultdict, Counter
from colorama import Fore, Style, init

init(autoreset=True)

# ============ CONFIG ============

DATA_DIR = os.path.expanduser("~/snihost_pro/isp_rules")
RULES_FILE = os.path.join(DATA_DIR, "inferred_rules.json")
PATTERNS_FILE = os.path.join(DATA_DIR, "discovered_patterns.json")
BURN_LOG = os.path.expanduser("~/snihost_pro/burn_test_log.json")
FEATURE_LOG = os.path.expanduser("~/snihost_pro/ml_data/feature_log.json")

os.makedirs(DATA_DIR, exist_ok=True)

# ============ PATTERN EXTRACTORS ============

def extract_domain_patterns(domain):
    """
    Extract all possible patterns from a domain name
    """
    patterns = []
    domain = domain.lower().strip()
    parts = domain.split('.')
    
    # TLD patterns
    if len(parts) >= 2:
        tld = '.'.join(parts[-2:])  # e.g., gov.ng
        patterns.append(('tld', tld))
    
    if len(parts) >= 3:
        gtld = '.'.join(parts[-3:])  # e.g., health.gov.ng
        patterns.append(('gtld', gtld))
    
    # Category keywords in domain
    category_keywords = {
        'health': ['health', 'hospital', 'medical', 'covid', 'vaccine', 'pharma', 'clinic'],
        'education': ['edu', 'school', 'university', 'college', 'academy', 'student', 'campus'],
        'government': ['gov', 'government', 'ministry', 'department', 'public', 'service'],
        'social': ['facebook', 'whatsapp', 'instagram', 'twitter', 'social', 'chat'],
        'cdn': ['cdn', 'cloud', 'static', 'assets', 'media', 'download'],
    }
    
    for cat, keywords in category_keywords.items():
        for kw in keywords:
            if kw in domain:
                patterns.append(('category_keyword', cat))
                break
    
    # Subdomain depth
    depth = len(parts)
    if depth <= 2:
        patterns.append(('depth', 'shallow'))
    elif depth == 3:
        patterns.append(('depth', 'medium'))
    else:
        patterns.append(('depth', 'deep'))
    
    # Specific subdomain prefixes
    prefixes = ['www', 'm', 'mobile', 'app', 'api', 'portal', 'mail', 'webmail', 
                'secure', 'admin', 'cdn', 'static', 'media']
    for prefix in prefixes:
        if domain.startswith(prefix + '.'):
            patterns.append(('subdomain_prefix', prefix))
            break
    
    return patterns

def extract_ip_patterns(ipv4_list):
    """
    Extract IP-based patterns
    """
    patterns = []
    
    for ip in ipv4_list:
        octets = ip.split('.')
        if len(octets) == 4:
            # /24 subnet
            patterns.append(('subnet', f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"))
            # /16 subnet
            patterns.append(('subnet', f"{octets[0]}.{octets[1]}.0.0/16"))
            # First octet only (broad)
            patterns.append(('ip_class', f"class_{octets[0]}"))
    
    return patterns

def extract_tls_patterns(tls_version, cipher_info=None):
    """
    Extract TLS configuration patterns
    """
    patterns = []
    
    if tls_version:
        # Group TLS versions
        if tls_version in ['TLSv1.0', 'TLSv1.1']:
            patterns.append(('tls_group', 'legacy'))
        elif tls_version == 'TLSv1.2':
            patterns.append(('tls_group', 'modern'))
        elif tls_version == 'TLSv1.3':
            patterns.append(('tls_group', 'latest'))
    
    return patterns

def extract_cdn_patterns(cdn_name):
    """
    Extract CDN patterns
    """
    patterns = []
    
    if cdn_name:
        patterns.append(('cdn', cdn_name))
    
    return patterns

# ============ RULE MINING ============

class ISPRuleMiner:
    """
    Mines rules from burn-test history using pattern analysis
    """
    
    def __init__(self, isp, country):
        self.isp = isp.lower().strip()
        self.country = country.lower().strip()
        self.worked_patterns = defaultdict(list)
        self.failed_patterns = defaultdict(list)
        self.rules = []
    
    def load_burn_data(self):
        """
        Load burn-test data for this ISP/country
        """
        if not os.path.exists(BURN_LOG):
            return []
        
        try:
            with open(BURN_LOG, 'r') as f:
                all_data = json.load(f)
        except:
            return []
        
        # Filter for this ISP/country
        filtered = []
        for entry in all_data:
            entry_isp = entry.get('isp', '').lower().strip()
            entry_country = entry.get('country', '').lower().strip()
            
            if entry_isp == self.isp and entry_country == self.country:
                filtered.append(entry)
        
        return filtered
    
    def load_features(self):
        """
        Load feature data for domains
        """
        if not os.path.exists(FEATURE_LOG):
            return {}
        
        try:
            with open(FEATURE_LOG, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def mine_patterns(self):
        """
        Mine patterns from worked vs failed hosts
        """
        burn_data = self.load_burn_data()
        features = self.load_features()
        
        if len(burn_data) < 10:
            print(f"{Fore.YELLOW}Need at least 10 burn-test results for {self.isp} ({self.country}){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}You have {len(burn_data)}. Run more tests.{Style.RESET_ALL}")
            return False
        
        worked_hosts = []
        failed_hosts = []
        
        for entry in burn_data:
            domain = entry.get('domain', '')
            worked = entry.get('worked', False)
            
            domain_features = features.get(domain, {})
            
            host_data = {
                'domain': domain,
                'worked': worked,
                'features': domain_features
            }
            
            if worked:
                worked_hosts.append(host_data)
            else:
                failed_hosts.append(host_data)
        
        print(f"\n{Fore.CYAN}Analyzing {len(worked_hosts)} working vs {len(failed_hosts)} failed hosts...{Style.RESET_ALL}")
        
        # Extract patterns from worked hosts
        worked_pattern_counts = Counter()
        for host in worked_hosts:
            patterns = self._extract_all_patterns(host)
            for p in patterns:
                worked_pattern_counts[p] += 1
        
        # Extract patterns from failed hosts
        failed_pattern_counts = Counter()
        for host in failed_hosts:
            patterns = self._extract_all_patterns(host)
            for p in patterns:
                failed_pattern_counts[p] += 1
        
        # Calculate confidence for each pattern
        self.rules = []
        
        all_patterns = set(worked_pattern_counts.keys()) | set(failed_pattern_counts.keys())
        
        for pattern in all_patterns:
            worked_count = worked_pattern_counts.get(pattern, 0)
            failed_count = failed_pattern_counts.get(pattern, 0)
            total = worked_count + failed_count
            
            if total < 3:  # Need minimum samples
                continue
            
            success_rate = (worked_count / total) * 100
            
            # Only keep patterns with strong signal
            if success_rate >= 70 and worked_count >= 2:
                self.rules.append({
                    'pattern': pattern,
                    'type': pattern[0],
                    'value': pattern[1],
                    'worked_count': worked_count,
                    'failed_count': failed_count,
                    'total_count': total,
                    'success_rate': round(success_rate, 1),
                    'confidence': 'HIGH' if success_rate >= 90 and total >= 5 else 'MEDIUM',
                    'recommendation': 'INCLUDE'  # Hosts matching this pattern likely work
                })
            elif success_rate <= 30 and failed_count >= 2:
                self.rules.append({
                    'pattern': pattern,
                    'type': pattern[0],
                    'value': pattern[1],
                    'worked_count': worked_count,
                    'failed_count': failed_count,
                    'total_count': total,
                    'success_rate': round(success_rate, 1),
                    'confidence': 'HIGH' if success_rate <= 10 and total >= 5 else 'MEDIUM',
                    'recommendation': 'EXCLUDE'  # Hosts matching this pattern likely fail
                })
        
        # Sort by success rate (highest first for INCLUDE, lowest first for EXCLUDE)
        self.rules.sort(key=lambda x: (-x['success_rate'] if x['recommendation'] == 'INCLUDE' else x['success_rate']))
        
        return True
    
    def _extract_all_patterns(self, host_data):
        """
        Extract all possible patterns from a host
        """
        patterns = []
        domain = host_data['domain']
        features = host_data.get('features', {})
        
        # Domain patterns
        patterns.extend(extract_domain_patterns(domain))
        
        # IP patterns
        ipv4 = features.get('ipv4', [])
        if isinstance(ipv4, list):
            patterns.extend(extract_ip_patterns(ipv4))
        
        # TLS patterns
        tls_version = features.get('tls_version_score')
        if tls_version is not None:
            # Map back to version name
            version_map = {3: 'TLSv1.3', 2: 'TLSv1.2', 1: 'TLSv1.1', 0: 'TLSv1.0'}
            if tls_version in version_map:
                patterns.extend(extract_tls_patterns(version_map[tls_version]))
        
        # CDN patterns
        cdn = features.get('cdn_score', 0)
        if cdn > 0:
            cdn_map = {3: 'cloudflare', 2: 'aws_cloudfront', 1: 'other'}
            cdn_name = cdn_map.get(cdn, 'unknown')
            patterns.extend(extract_cdn_patterns(cdn_name))
        
        # Category
        cat_score = features.get('category_score', 0)
        cat_map = {5: 'government', 4: 'education', 3: 'health', 2: 'social', 1: 'cdn', 0: 'other'}
        if cat_score in cat_map:
            patterns.append(('category', cat_map[cat_score]))
        
        return patterns
    
    def predict_host(self, domain, features=None):
        """
        Predict if a new host will work based on mined rules
        """
        if not self.rules:
            return {
                'domain': domain,
                'predictable': False,
                'message': 'No rules mined yet. Run rule mining first.'
            }
        
        # Extract patterns for this host
        host_data = {'domain': domain, 'features': features or {}}
        host_patterns = self._extract_all_patterns(host_data)
        
        matching_include = []
        matching_exclude = []
        
        for rule in self.rules:
            if rule['pattern'] in host_patterns:
                if rule['recommendation'] == 'INCLUDE':
                    matching_include.append(rule)
                else:
                    matching_exclude.append(rule)
        
        # Calculate score
        include_score = sum(r['success_rate'] * (2 if r['confidence'] == 'HIGH' else 1) 
                           for r in matching_include)
        exclude_score = sum((100 - r['success_rate']) * (2 if r['confidence'] == 'HIGH' else 1) 
                           for r in matching_exclude)
        
        total_weight = len(matching_include) + len(matching_exclude)
        
        if total_weight == 0:
            return {
                'domain': domain,
                'predictable': True,
                'prediction': 'UNKNOWN',
                'confidence': 0,
                'message': 'No matching rules found',
                'matching_rules': []
            }
        
        final_score = (include_score - exclude_score) / (total_weight * 100) * 100
        final_score = max(0, min(100, final_score + 50))  # Normalize to 0-100
        
        if final_score >= 70:
            prediction = 'LIKELY_WORKS'
            color = Fore.GREEN
        elif final_score >= 40:
            prediction = 'UNCERTAIN'
            color = Fore.YELLOW
        else:
            prediction = 'LIKELY_FAILS'
            color = Fore.RED
        
        return {
            'domain': domain,
            'predictable': True,
            'prediction': prediction,
            'confidence': round(final_score, 1),
            'matching_include': len(matching_include),
            'matching_exclude': len(matching_exclude),
            'include_rules': matching_include,
            'exclude_rules': matching_exclude,
            'message': f"{color}{prediction}{Style.RESET_ALL} ({round(final_score, 1)}% confidence)"
        }
    
    def save_rules(self):
        """Save mined rules to file"""
        data = {
            'metadata': {
                'isp': self.isp,
                'country': self.country,
                'mined_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_rules': len(self.rules),
                'include_rules': len([r for r in self.rules if r['recommendation'] == 'INCLUDE']),
                'exclude_rules': len([r for r in self.rules if r['recommendation'] == 'EXCLUDE'])
            },
            'rules': self.rules
        }
        
        filename = f"rules_{self.isp}_{self.country}_{time.strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(DATA_DIR, filename)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Also save as latest
        latest_path = os.path.join(DATA_DIR, f"latest_{self.isp}_{self.country}.json")
        with open(latest_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"{Fore.GREEN}Rules saved to: {filepath}{Style.RESET_ALL}")
        return filepath
    
    def display_rules(self):
        """Display mined rules"""
        if not self.rules:
            print(f"{Fore.YELLOW}No rules mined yet{Style.RESET_ALL}")
            return
        
        include_rules = [r for r in self.rules if r['recommendation'] == 'INCLUDE']
        exclude_rules = [r for r in self.rules if r['recommendation'] == 'EXCLUDE']
        
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  INCLUDE Rules (These patterns LIKELY WORK){Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        for i, rule in enumerate(include_rules[:10], 1):
            conf_color = Fore.GREEN if rule['confidence'] == 'HIGH' else Fore.YELLOW
            print(f"\n  {i}. {rule['type']} = {rule['value']}")
            print(f"     Success Rate: {Fore.GREEN}{rule['success_rate']}%{Style.RESET_ALL}")
            print(f"     Samples: {rule['worked_count']}/{rule['total_count']} worked")
            print(f"     Confidence: {conf_color}{rule['confidence']}{Style.RESET_ALL}")
        
        if exclude_rules:
            print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.RED}  EXCLUDE Rules (These patterns LIKELY FAIL){Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
            
            for i, rule in enumerate(exclude_rules[:5], 1):
                conf_color = Fore.RED if rule['confidence'] == 'HIGH' else Fore.YELLOW
                print(f"\n  {i}. {rule['type']} = {rule['value']}")
                print(f"     Success Rate: {Fore.RED}{rule['success_rate']}%{Style.RESET_ALL}")
                print(f"     Samples: {rule['worked_count']}/{rule['total_count']} worked")
                print(f"     Confidence: {conf_color}{rule['confidence']}{Style.RESET_ALL}")

# ============ MAIN INTERFACE ============

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  ISP Rule Inference{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Discover Your ISP's Zero-Rating Patterns{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Mine rules from burn-test history")
    print("2. Predict single host using mined rules")
    print("3. Batch predict hosts from file")
    print("4. View saved rules")
    
    choice = input("\nChoice (1-4): ").strip()
    
    if choice == '1':
        isp = input("Your ISP: ").strip()
        country = input("Your Country: ").strip()
        
        miner = ISPRuleMiner(isp, country)
        success = miner.mine_patterns()
        
        if success:
            miner.display_rules()
            miner.save_rules()
            
            print(f"\n{Fore.GREEN}Rule mining complete!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}These rules are specific to {isp} in {country}.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Test more hosts to improve accuracy.{Style.RESET_ALL}")
    
    elif choice == '2':
        isp = input("Your ISP: ").strip()
        country = input("Your Country: ").strip()
        domain = input("Domain to predict: ").strip().lower()
        
        # Load latest rules
        latest_file = os.path.join(DATA_DIR, f"latest_{isp.lower()}_{country.lower()}.json")
        
        if not os.path.exists(latest_file):
            print(f"{Fore.RED}No rules found for {isp} ({country}). Mine rules first (Option 1).{Style.RESET_ALL}")
            return
        
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        miner = ISPRuleMiner(isp, country)
        miner.rules = data.get('rules', [])
        
        # Load features for this domain if available
        features = {}
        if os.path.exists(FEATURE_LOG):
            with open(FEATURE_LOG, 'r') as f:
                all_features = json.load(f)
                features = all_features.get(domain, {})
        
        prediction = miner.predict_host(domain, features)
        
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Prediction for: {domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"  Result: {prediction['message']}")
        print(f"  Confidence: {prediction.get('confidence', 0)}%")
        
        if prediction.get('matching_include', 0) > 0:
            print(f"\n  Matching INCLUDE rules:")
            for rule in prediction.get('include_rules', [])[:3]:
                print(f"    + {rule['type']} = {rule['value']} ({rule['success_rate']}%)")
        
        if prediction.get('matching_exclude', 0) > 0:
            print(f"\n  Matching EXCLUDE rules:")
            for rule in prediction.get('exclude_rules', [])[:3]:
                print(f"    - {rule['type']} = {rule['value']} ({rule['success_rate']}%)")
    
    elif choice == '3':
        isp = input("Your ISP: ").strip()
        country = input("Your Country: ").strip()
        
        latest_file = os.path.join(DATA_DIR, f"latest_{isp.lower()}_{country.lower()}.json")
        
        if not os.path.exists(latest_file):
            print(f"{Fore.RED}No rules found. Mine rules first.{Style.RESET_ALL}")
            return
        
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        miner = ISPRuleMiner(isp, country)
        miner.rules = data.get('rules', [])
        
        print("Enter domains (one per line, empty line to finish):")
        domains = []
        while True:
            line = input().strip().lower()
            if not line:
                break
            domains.append(line)
        
        # Load all features
        all_features = {}
        if os.path.exists(FEATURE_LOG):
            with open(FEATURE_LOG, 'r') as f:
                all_features = json.load(f)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Batch Predictions for {isp} ({country}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        predictions = []
        for domain in domains:
            features = all_features.get(domain, {})
            pred = miner.predict_host(domain, features)
            predictions.append((domain, pred))
        
        # Sort by confidence
        predictions.sort(key=lambda x: x[1].get('confidence', 0), reverse=True)
        
        for i, (domain, pred) in enumerate(predictions, 1):
            conf = pred.get('confidence', 0)
            color = Fore.GREEN if conf >= 70 else Fore.YELLOW if conf >= 40 else Fore.RED
            status = pred.get('prediction', 'UNKNOWN')
            print(f"\n  {i}. {color}{domain}{Style.RESET_ALL}")
            print(f"     Prediction: {status} ({conf}%)")
    
    elif choice == '4':
        files = [f for f in os.listdir(DATA_DIR) if f.endswith('.json')]
        
        if not files:
            print(f"{Fore.YELLOW}No saved rules found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Saved rule files:{Style.RESET_ALL}")
        for i, f in enumerate(files, 1):
            print(f"  {i}. {f}")
        
        file_choice = input("\nEnter number to view: ").strip()
        if file_choice.isdigit() and 1 <= int(file_choice) <= len(files):
            filepath = os.path.join(DATA_DIR, files[int(file_choice)-1])
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            meta = data.get('metadata', {})
            print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Rules for {meta.get('isp', 'Unknown')} ({meta.get('country', 'Unknown')}){Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Mined: {meta.get('mined_at', 'Unknown')}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  Total Rules: {meta.get('total_rules', 0)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            
            rules = data.get('rules', [])
            for rule in rules:
                color = Fore.GREEN if rule['recommendation'] == 'INCLUDE' else Fore.RED
                print(f"\n  {color}[{rule['recommendation']}]{Style.RESET_ALL} {rule['type']} = {rule['value']}")
                print(f"     Rate: {rule['success_rate']}% ({rule['worked_count']}/{rule['total_count']})")
                print(f"     Confidence: {rule['confidence']}")
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

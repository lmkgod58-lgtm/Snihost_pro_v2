#!/usr/bin/env python3
"""
Community Intelligence Module
SOUTH AFRICA EDITION
Anonymous crowdsourced database with SA-specific fields:
- MTN 500MB cap tracking
- Rural area testing
- Registration required (Open Time)
- Content type verification
- Spectrum status (Cell C)
"""

import json
import os
import time
import hashlib
from colorama import Fore, Style, init

init(autoreset=True)

COMMUNITY_DIR = os.path.expanduser("~/snihost_pro/community")
LOCAL_DB = os.path.join(COMMUNITY_DIR, "sa_local_intel.json")
os.makedirs(COMMUNITY_DIR, exist_ok=True)

# ============ SA-SPECIFIC INTEL ENTRY ============

class SAIntelEntry:
    """
    SA-specific intelligence entry with extra fields
    """
    
    def __init__(self, domain, isp, country, worked, timestamp=None,
                 user_hash=None, notes="", tls_version=None,
                 http_status=None, score=None,
                 # SA-specific fields
                 data_cap_reached=None,      # MTN 500MB cap hit?
                 rural_area=None,             # Did it work in rural area?
                 registration_needed=None,    # MTN Open Time reg required?
                 content_type_matched=None,     # Did content look legitimate?
                 actual_data_used_mb=None,    # How much data was used
                 connection_speed_mbps=None,   # Speed test result
                 cap_limit_mb=None,           # ISP cap if known (500 for MTN)
                 spectrum_returned=None,      # Cell C spectrum status
                 province=None,               # SA province tested from
                 ):
        
        self.domain = domain.lower().strip()
        self.isp = isp.lower().strip()
        self.country = country.lower().strip()
        self.worked = bool(worked)
        self.timestamp = timestamp or time.strftime('%Y-%m-%d %H:%M:%S')
        self.user_hash = user_hash or self._generate_user_hash()
        self.notes = notes
        self.tls_version = tls_version
        self.http_status = http_status
        self.score = score
        
        # SA-specific
        self.data_cap_reached = data_cap_reached
        self.rural_area = rural_area
        self.registration_needed = registration_needed
        self.content_type_matched = content_type_matched
        self.actual_data_used_mb = actual_data_used_mb
        self.connection_speed_mbps = connection_speed_mbps
        self.cap_limit_mb = cap_limit_mb or (500 if self.isp == 'mtn' else None)
        self.spectrum_returned = spectrum_returned or (self.isp in ['cell_c', 'cellc'])
        self.province = province
    
    def _generate_user_hash(self):
        seed = f"{os.uname().nodename}{os.getuid()}{time.time()}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]
    
    def to_dict(self):
        return {
            'domain': self.domain,
            'isp': self.isp,
            'country': self.country,
            'worked': self.worked,
            'timestamp': self.timestamp,
            'user_hash': self.user_hash,
            'notes': self.notes,
            'tls_version': self.tls_version,
            'http_status': self.http_status,
            'score': self.score,
            # SA-specific
            'data_cap_reached': self.data_cap_reached,
            'rural_area': self.rural_area,
            'registration_needed': self.registration_needed,
            'content_type_matched': self.content_type_matched,
            'actual_data_used_mb': self.actual_data_used_mb,
            'connection_speed_mbps': self.connection_speed_mbps,
            'cap_limit_mb': self.cap_limit_mb,
            'spectrum_returned': self.spectrum_returned,
            'province': self.province,
        }
    
    @classmethod
    def from_dict(cls, d):
        return cls(
            domain=d.get('domain', ''),
            isp=d.get('isp', ''),
            country=d.get('country', ''),
            worked=d.get('worked', False),
            timestamp=d.get('timestamp'),
            user_hash=d.get('user_hash'),
            notes=d.get('notes', ''),
            tls_version=d.get('tls_version'),
            http_status=d.get('http_status'),
            score=d.get('score'),
            data_cap_reached=d.get('data_cap_reached'),
            rural_area=d.get('rural_area'),
            registration_needed=d.get('registration_needed'),
            content_type_matched=d.get('content_type_matched'),
            actual_data_used_mb=d.get('actual_data_used_mb'),
            connection_speed_mbps=d.get('connection_speed_mbps'),
            cap_limit_mb=d.get('cap_limit_mb'),
            spectrum_returned=d.get('spectrum_returned'),
            province=d.get('province'),
        )

# ============ DATABASE ============

class SACommunityDatabase:
    
    def __init__(self):
        self.entries = []
        self.load()
    
    def load(self):
        if os.path.exists(LOCAL_DB):
            try:
                with open(LOCAL_DB, 'r') as f:
                    data = json.load(f)
                    self.entries = [SAIntelEntry.from_dict(e) for e in data.get('entries', [])]
            except:
                self.entries = []
        else:
            self.entries = []
    
    def save(self):
        data = {
            'metadata': {
                'version': '2.0_sa',
                'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_entries': len(self.entries)
            },
            'entries': [e.to_dict() for e in self.entries]
        }
        with open(LOCAL_DB, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_entry(self, entry):
        # Update if same domain+isp+user within 24h
        for existing in self.entries:
            if (existing.domain == entry.domain and 
                existing.isp == entry.isp and 
                existing.user_hash == entry.user_hash):
                existing.worked = entry.worked
                existing.timestamp = entry.timestamp
                existing.notes = entry.notes
                existing.score = entry.score
                existing.data_cap_reached = entry.data_cap_reached
                existing.rural_area = entry.rural_area
                existing.registration_needed = entry.registration_needed
                existing.content_type_matched = entry.content_type_matched
                existing.actual_data_used_mb = entry.actual_data_used_mb
                self.save()
                return
        
        self.entries.append(entry)
        self.save()
    
    def get_entries(self, domain=None, isp=None, country=None, worked_only=True):
        results = []
        for e in self.entries:
            if domain and e.domain != domain.lower():
                continue
            if isp and e.isp != isp.lower():
                continue
            if country and e.country != country.lower():
                continue
            if worked_only and not e.worked:
                continue
            results.append(e)
        return results
    
    def get_isp_stats(self, isp, country):
        entries = self.get_entries(isp=isp, country=country, worked_only=False)
        
        if not entries:
            return None
        
        worked = sum(1 for e in entries if e.worked)
        failed = len(entries) - worked
        
        # SA-specific stats
        cap_hits = sum(1 for e in entries if e.data_cap_reached)
        rural_works = sum(1 for e in entries if e.rural_area and e.worked)
        content_match = sum(1 for e in entries if e.content_type_matched and e.worked)
        
        unique_domains = set(e.domain for e in entries)
        working_domains = set(e.domain for e in entries if e.worked)
        
        return {
            'isp': isp,
            'country': country,
            'total_reports': len(entries),
            'worked': worked,
            'failed': failed,
            'success_rate': round((worked / len(entries)) * 100, 1) if entries else 0,
            'unique_domains_tested': len(unique_domains),
            'unique_working_domains': len(working_domains),
            'cap_hits': cap_hits,
            'rural_success': rural_works,
            'content_match_success': content_match,
            'last_report': max(e.timestamp for e in entries) if entries else None
        }
    
    def get_domain_stats(self, domain):
        entries = [e for e in self.entries if e.domain == domain.lower()]
        
        if not entries:
            return None
        
        worked = sum(1 for e in entries if e.worked)
        isps = set((e.isp, e.country) for e in entries)
        
        # SA-specific
        avg_data_used = sum(e.actual_data_used_mb or 0 for e in entries if e.actual_data_used_mb) / \
                       max(1, sum(1 for e in entries if e.actual_data_used_mb))
        
        return {
            'domain': domain,
            'total_reports': len(entries),
            'worked': worked,
            'failed': len(entries) - worked,
            'success_rate': round((worked / len(entries)) * 100, 1) if entries else 0,
            'isps': [f"{isp} ({country})" for isp, country in isps],
            'avg_data_used_mb': round(avg_data_used, 1),
            'last_report': max(e.timestamp for e in entries) if entries else None
        }
    
    def get_trending(self, country=None, days=7, limit=20):
        cutoff = time.time() - (days * 86400)
        recent = []
        
        for e in self.entries:
            try:
                entry_time = time.mktime(time.strptime(e.timestamp, '%Y-%m-%d %H:%M:%S'))
                if entry_time >= cutoff:
                    if country is None or e.country == country.lower():
                        recent.append(e)
            except:
                pass
        
        domain_counts = {}
        for e in recent:
            if e.worked:
                if e.domain not in domain_counts:
                    domain_counts[e.domain] = {
                        'count': 0, 'isps': set(), 'last_seen': e.timestamp,
                        'rural': 0, 'cap_hits': 0
                    }
                domain_counts[e.domain]['count'] += 1
                domain_counts[e.domain]['isps'].add(f"{e.isp} ({e.country})")
                if e.rural_area:
                    domain_counts[e.domain]['rural'] += 1
                if e.data_cap_reached:
                    domain_counts[e.domain]['cap_hits'] += 1
                if e.timestamp > domain_counts[e.domain]['last_seen']:
                    domain_counts[e.domain]['last_seen'] = e.timestamp
        
        sorted_domains = sorted(domain_counts.items(), key=lambda x: -x[1]['count'])
        
        return [(d, info['count'], list(info['isps']), info['last_seen'], info['rural'], info['cap_hits'])
                for d, info in sorted_domains[:limit]]

# ============ SUBMISSION ============

class SAIntelSubmitter:
    
    def __init__(self):
        self.db = SACommunityDatabase()
    
    def submit(self, domain, isp, country, worked, notes="",
               tls_version=None, http_status=None, score=None,
               data_cap_reached=None, rural_area=None,
               registration_needed=None, content_type_matched=None,
               actual_data_used_mb=None, connection_speed_mbps=None,
               province=None):
        
        entry = SAIntelEntry(
            domain=domain, isp=isp, country=country, worked=worked,
            notes=notes, tls_version=tls_version, http_status=http_status,
            score=score, data_cap_reached=data_cap_reached,
            rural_area=rural_area, registration_needed=registration_needed,
            content_type_matched=content_type_matched,
            actual_data_used_mb=actual_data_used_mb,
            connection_speed_mbps=connection_speed_mbps,
            province=province
        )
        
        self.db.add_entry(entry)
        print(f"{Fore.GREEN}✓ Saved to SA community DB{Style.RESET_ALL}")
        return entry

# ============ QUERY ============

class SAIntelQuery:
    
    def __init__(self):
        self.db = SACommunityDatabase()
    
    def check_host(self, domain, isp=None, country=None):
        domain = domain.lower().strip()
        entries = self.db.get_entries(domain=domain, isp=isp, country=country, worked_only=False)
        
        if not entries:
            return {
                'domain': domain,
                'known': False,
                'message': f"No SA community data for {domain}"
            }
        
        worked = sum(1 for e in entries if e.worked)
        total = len(entries)
        rate = (worked / total) * 100 if total else 0
        
        # SA-specific insights
        cap_warnings = sum(1 for e in entries if e.data_cap_reached)
        rural_reports = sum(1 for e in entries if e.rural_area)
        rural_worked = sum(1 for e in entries if e.rural_area and e.worked)
        reg_needed = any(e.registration_needed for e in entries if e.worked)
        content_ok = sum(1 for e in entries if e.content_type_matched and e.worked)
        
        return {
            'domain': domain,
            'known': True,
            'total_reports': total,
            'worked': worked,
            'failed': total - worked,
            'success_rate': round(rate, 1),
            'isps': list(set(f"{e.isp} ({e.country})" for e in entries)),
            'last_report': max(e.timestamp for e in entries),
            'recent_working': any(e.worked for e in entries[-5:]) if len(entries) >= 5 else worked > 0,
            # SA-specific
            'cap_warnings': cap_warnings,
            'rural_reports': rural_reports,
            'rural_worked': rural_worked,
            'registration_needed': reg_needed,
            'content_verified': content_ok,
        }
    
    def get_recommendations(self, isp, country, limit=10):
        entries = self.db.get_entries(isp=isp, country=country, worked_only=True)
        
        if not entries:
            return []
        
        domain_scores = {}
        for e in entries:
            if e.domain not in domain_scores:
                domain_scores[e.domain] = {
                    'reports': 0, 'last_seen': e.timestamp,
                    'avg_score': [], 'rural_bonus': 0,
                    'content_bonus': 0, 'no_cap_bonus': 0
                }
            domain_scores[e.domain]['reports'] += 1
            domain_scores[e.domain]['avg_score'].append(e.score or 0)
            if e.timestamp > domain_scores[e.domain]['last_seen']:
                domain_scores[e.domain]['last_seen'] = e.timestamp
            if e.rural_area:
                domain_scores[e.domain]['rural_bonus'] += 5
            if e.content_type_matched:
                domain_scores[e.domain]['content_bonus'] += 3
            if not e.data_cap_reached:
                domain_scores[e.domain]['no_cap_bonus'] += 2
        
        scored = []
        for domain, info in domain_scores.items():
            avg_score = sum(info['avg_score']) / len(info['avg_score']) if info['avg_score'] else 0
            recency_bonus = 10 if info['last_seen'] > time.strftime('%Y-%m-%d', time.localtime(time.time() - 86400)) else 0
            final_score = (info['reports'] * 10) + avg_score + recency_bonus + \
                         info['rural_bonus'] + info['content_bonus'] + info['no_cap_bonus']
            scored.append((domain, final_score, info['reports'], info['last_seen']))
        
        scored.sort(key=lambda x: -x[1])
        return scored[:limit]

# ============ DISPLAY ============

def display_host_intel(intel):
    if not intel['known']:
        print(f"\n{Fore.YELLOW}⚠ {intel['message']}{Style.RESET_ALL}")
        return
    
    rate_color = Fore.GREEN if intel['success_rate'] >= 70 else Fore.YELLOW if intel['success_rate'] >= 40 else Fore.RED
    
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SA Community Intel: {intel['domain']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"  Reports: {intel['total_reports']}")
    print(f"  Worked: {Fore.GREEN}{intel['worked']}{Style.RESET_ALL}")
    print(f"  Failed: {Fore.RED}{intel['failed']}{Style.RESET_ALL}")
    print(f"  Success Rate: {rate_color}{intel['success_rate']}%{Style.RESET_ALL}")
    print(f"  ISPs: {', '.join(intel['isps'])}")
    print(f"  Last Report: {intel['last_report']}")
    
    # SA-specific
    print(f"\n  {Fore.CYAN}SA-Specific Insights:{Style.RESET_ALL}")
    if intel.get('cap_warnings', 0) > 0:
        print(f"  ⚠️ Cap warnings: {intel['cap_warnings']} (MTN 500MB limit)")
    if intel.get('rural_reports', 0) > 0:
        rural_rate = (intel['rural_worked'] / intel['rural_reports'] * 100) if intel['rural_reports'] else 0
        print(f"  🏞️ Rural success: {rural_rate:.0f}% ({intel['rural_worked']}/{intel['rural_reports']})")
    if intel.get('registration_needed'):
        print(f"  📝 Registration required (MTN Open Time)")
    if intel.get('content_verified', 0) > 0:
        print(f"  ✅ Content verified: {intel['content_verified']} reports")
    
    if intel.get('recent_working'):
        print(f"\n  {Fore.GREEN}✓ Recently reported working!{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.RED}✗ Recent reports indicate failure{Style.RESET_ALL}")

def display_recommendations(recs, isp, country):
    if not recs:
        print(f"\n{Fore.YELLOW}No SA recommendations for {isp} ({country}){Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Top SA Recommendations for {isp} ({country}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    for i, (domain, score, reports, last_seen) in enumerate(recs, 1):
        print(f"\n  {i}. {Fore.GREEN}{domain}{Style.RESET_ALL}")
        print(f"     SA Score: {score:.1f}")
        print(f"     Reports: {reports}")
        print(f"     Last: {last_seen}")

def display_trending(trending):
    if not trending:
        print(f"\n{Fore.YELLOW}No trending hosts{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Trending SA Working Hosts (7 days){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    for i, (domain, count, isps, last_seen, rural, cap_hits) in enumerate(trending, 1):
        rural_marker = f" 🏞️{rural}" if rural else ""
        cap_marker = f" ⚠️{cap_hits}" if cap_hits else ""
        print(f"\n  {i}. {Fore.GREEN}{domain}{Style.RESET_ALL}")
        print(f"     Reports: {count}{rural_marker}{cap_marker}")
        print(f"     ISPs: {', '.join(isps)}")
        print(f"     Last: {last_seen}")

# ============ MAIN ============

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SA Community Intelligence{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Submit SA burn-test result")
    print("2. Check SA host intel")
    print("3. SA recommendations")
    print("4. SA trending hosts")
    print("5. SA ISP statistics")
    print("6. Database status")
    
    choice = input("\nChoice (1-6): ").strip()
    
    if choice == '1':
        print(f"\n{Fore.YELLOW}Submit SA burn-test:{Style.RESET_ALL}")
        domain = input("Domain: ").strip().lower()
        isp = input("ISP (MTN/Vodacom/Telkom/Cell C): ").strip()
        country = input("Country: ").strip() or "South Africa"
        worked = input("Worked? (y/n): ").strip().lower() == 'y'
        notes = input("Notes: ").strip()
        tls = input("TLS version: ").strip() or None
        status = input("HTTP status: ").strip()
        status = int(status) if status.isdigit() else None
        score = input("Score: ").strip()
        score = int(score) if score.isdigit() else None
        
        # SA-specific
        print(f"\n{Fore.CYAN}SA-Specific Details:{Style.RESET_ALL}")
        cap_reached = input("Did you hit data cap? (y/n): ").strip().lower() == 'y' if isp.lower() == 'mtn' else None
        rural = input("Tested in rural area? (y/n): ").strip().lower() == 'y'
        reg_needed = input("Registration required? (y/n): ").strip().lower() == 'y' if isp.lower() == 'mtn' else None
        content_ok = input("Content looked legitimate? (y/n): ").strip().lower() == 'y'
        data_used = input("Data used (MB): ").strip()
        data_used = float(data_used) if data_used else None
        speed = input("Connection speed (Mbps): ").strip()
        speed = float(speed) if speed else None
        province = input("Province (e.g., Gauteng, KZN): ").strip() or None
        
        submitter = SAIntelSubmitter()
        submitter.submit(
            domain, isp, country, worked, notes, tls, status, score,
            data_cap_reached=cap_reached, rural_area=rural,
            registration_needed=reg_needed, content_type_matched=content_ok,
            actual_data_used_mb=data_used, connection_speed_mbps=speed,
            province=province
        )
        print(f"\n{Fore.GREEN}Thank you for contributing to SA intel!{Style.RESET_ALL}")
    
    elif choice == '2':
        domain = input("Domain: ").strip().lower()
        isp = input("ISP (optional): ").strip() or None
        country = input("Country (optional): ").strip() or None
        
        query = SAIntelQuery()
        intel = query.check_host(domain, isp, country)
        display_host_intel(intel)
    
    elif choice == '3':
        isp = input("ISP: ").strip()
        country = input("Country: ").strip() or "South Africa"
        
        query = SAIntelQuery()
        recs = query.get_recommendations(isp, country)
        display_recommendations(recs, isp, country)
    
    elif choice == '4':
        country = input("Country filter (optional): ").strip() or None
        db = SACommunityDatabase()
        trending = db.get_trending(country=country)
        display_trending(trending)
    
    elif choice == '5':
        isp = input("ISP: ").strip()
        country = input("Country: ").strip() or "South Africa"
        
        db = SACommunityDatabase()
        stats = db.get_isp_stats(isp, country)
        
        if stats:
            print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  SA ISP Stats: {isp} ({country}){Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            print(f"  Total: {stats['total_reports']}")
            print(f"  Worked: {Fore.GREEN}{stats['worked']}{Style.RESET_ALL}")
            print(f"  Failed: {Fore.RED}{stats['failed']}{Style.RESET_ALL}")
            print(f"  Rate: {stats['success_rate']}%")
            print(f"  Domains: {stats['unique_domains_tested']}")
            print(f"  Working: {stats['unique_working_domains']}")
            print(f"\n  SA-Specific:")
            print(f"  Cap hits: {stats['cap_hits']}")
            print(f"  Rural success: {stats['rural_success']}")
            print(f"  Content match: {stats['content_match_success']}")
        else:
            print(f"{Fore.YELLOW}No data for {isp}{Style.RESET_ALL}")
    
    elif choice == '6':
        db = SACommunityDatabase()
        print(f"\n{Fore.CYAN}SA Database Status{Style.RESET_ALL}")
        print(f"  Entries: {len(db.entries)}")
        
        isps = set((e.isp, e.country) for e in db.entries)
        print(f"  ISPs: {len(isps)}")
        
        domains = set(e.domain for e in db.entries)
        print(f"  Domains: {len(domains)}")
        
        worked = sum(1 for e in db.entries if e.worked)
        print(f"  Working: {worked}")
        print(f"  Failed: {len(db.entries) - worked}")
        
        # SA-specific breakdown
        cap_hits = sum(1 for e in db.entries if e.data_cap_reached)
        rural = sum(1 for e in db.entries if e.rural_area)
        print(f"\n  SA Breakdown:")
        print(f"  Cap hits: {cap_hits}")
        print(f"  Rural tests: {rural}")
        print(f"  Registration needed: {sum(1 for e in db.entries if e.registration_needed)}")
        
        if isps:
            print(f"\n  ISPs:")
            for isp, country in sorted(isps):
                print(f"    - {isp} ({country})")
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

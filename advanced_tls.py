#!/usr/bin/env python3
"""
Advanced TLS Tests Module
SOUTH AFRICA EDITION
Tests hosts for exploitable TLS configurations with SA ISP awareness:
- MTN tunnel ban detection
- Vodacom strict SNI verification
- Telkom education portal compatibility
- Content-type legitimacy checks
"""

import socket
import ssl
import time
import json
import os
from colorama import Fore, Style, init

init(autoreset=True)

RESULTS_DIR = os.path.expanduser("~/snihost_pro/results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# SA ISP-specific TLS signatures
SA_ISP_TLS_PROFILES = {
    'mtn': {
        'bans_tunneling': True,
        'checks_ja3': True,
        'traffic_shaping': True,
        'preferred_versions': ['TLSv1.3', 'TLSv1.2'],
        'rejects_legacy': True,  # MTN prefers modern TLS
    },
    'vodacom': {
        'strict_sni_verification': True,
        'checks_cert_sans': True,
        'verifies_ip_sni_match': True,
        'preferred_versions': ['TLSv1.3', 'TLSv1.2'],
    },
    'telkom': {
        'education_portal_strict': True,
        'checks_content_type': True,
        'accepts_legacy': True,  # Telkom more lenient
    },
    'cell_c': {
        'similar_to_vodacom': True,
        'less_strict': True,
        'accepts_legacy': True,
    }
}

LEGACY_CIPHERS = [
    'AES128-SHA', 'AES256-SHA', 'DES-CBC3-SHA',
    'RC4-SHA', 'RC4-MD5',
    'DHE-RSA-AES128-SHA', 'DHE-RSA-AES256-SHA',
]

MODERN_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
]

# ============ BASIC TLS TESTS ============

def test_tls_handshake(domain, timeout=5, sni=None):
    """
    Test TLS handshake with optional custom SNI
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        start = time.time()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=(sni or domain)) as ssock:
                elapsed = (time.time() - start) * 1000
                cipher = ssock.cipher()
                version = ssock.version()
                cert = ssock.getpeercert()
                
                return {
                    'success': True,
                    'tls_version': version,
                    'cipher': cipher[0] if cipher else None,
                    'cipher_bits': cipher[2] if cipher else 0,
                    'response_time_ms': round(elapsed, 2),
                    'cert_sans': [s[1] for s in cert.get('subjectAltName', [])] if cert else [],
                    'cert_issuer': str(cert.get('issuer', '')) if cert else '',
                    'cert_subject': str(cert.get('subject', '')) if cert else '',
                    'cert_not_after': cert.get('notAfter') if cert else None,
                }
    except Exception as e:
        return {'success': False, 'error': str(e)}

# ============ SA-SPECIFIC TESTS ============

def test_mtn_tunnel_detection(domain, timeout=5):
    """
    MTN explicitly bans tunneling in T&Cs.
    This tests if the connection looks like a tunnel.
    """
    print(f"    {Fore.YELLOW}[SA] MTN tunnel signature check...{Style.RESET_ALL}", end=' ')
    
    try:
        # MTN may detect based on:
        # 1. Unusual cipher suites
        # 2. Missing browser-like extensions
        # 3. Perfect forward secrecy patterns
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Tunnel-like signatures to avoid
                tunnel_risk = 0
                
                # Old ciphers = more suspicious to MTN
                if version in ['TLSv1.0', 'TLSv1.1']:
                    tunnel_risk += 20
                
                # Weak ciphers = suspicious
                if cipher and any(old in cipher[0] for old in ['RC4', 'DES', '3DES', 'MD5']):
                    tunnel_risk += 15
                
                # No SNI = very suspicious
                # (already tested separately)
                
                if tunnel_risk == 0:
                    print(f"{Fore.GREEN}CLEAN{Style.RESET_ALL}")
                    return {'tunnel_risk': 0, 'looks_clean': True}
                else:
                    print(f"{Fore.YELLOW}RISK {tunnel_risk}%{Style.RESET_ALL}")
                    return {'tunnel_risk': tunnel_risk, 'looks_clean': False}
                    
    except Exception as e:
        print(f"{Fore.RED}ERROR{Style.RESET_ALL}")
        return {'tunnel_risk': 50, 'looks_clean': False, 'error': str(e)}

def test_vodacom_strict_sni(domain, timeout=5):
    """
    Vodacom verifies IP + Port + SNI all match.
    This tests strict SNI compliance.
    """
    print(f"    {Fore.YELLOW}[SA] Vodacom strict SNI check...{Style.RESET_ALL}", end=' ')
    
    try:
        # Test 1: Correct SNI
        correct = test_tls_handshake(domain, timeout, sni=domain)
        
        # Test 2: Wrong SNI (should fail or return different cert)
        wrong = test_tls_handshake(domain, timeout, sni='google.com')
        
        if not correct['success']:
            print(f"{Fore.RED}BASIC TLS FAIL{Style.RESET_ALL}")
            return {'strict_sni': False, 'error': 'Basic TLS failed'}
        
        # Check if wrong SNI is rejected
        if not wrong['success']:
            # Good: Vodacom would reject wrong SNI
            print(f"{Fore.GREEN}STRICT (rejects wrong SNI){Style.RESET_ALL}")
            return {
                'strict_sni': True,
                'rejects_wrong_sni': True,
                'vodacom_compatible': True
            }
        else:
            # Server accepts wrong SNI — may be shared hosting
            print(f"{Fore.YELLOW}LENIENT (accepts wrong SNI){Style.RESET_ALL}")
            return {
                'strict_sni': False,
                'rejects_wrong_sni': False,
                'shared_hosting': True,
                'vodacom_compatible': False  # Vodacom may reject
            }
            
    except Exception as e:
        print(f"{Fore.RED}ERROR{Style.RESET_ALL}")
        return {'strict_sni': False, 'error': str(e)}

def test_telkom_edu_portal(domain, timeout=5):
    """
    Telkom checks if site is on official education portal.
    Tests for education-specific markers.
    """
    print(f"    {Fore.YELLOW}[SA] Telkom edu portal check...{Style.RESET_ALL}", end=' ')
    
    edu_markers = [
        'moodle', 'learn', 'elearning', 'courses', 'student',
        'academic', 'campus', 'lecture', 'module', 'faculty'
    ]
    
    try:
        import http.client
        conn = http.client.HTTPSConnection(domain, timeout=timeout)
        conn.request("GET", "/", headers={
            'Host': domain,
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10)'
        })
        resp = conn.getresponse()
        body = resp.read(2000).decode('utf-8', errors='ignore').lower()
        conn.close()
        
        matches = sum(1 for marker in edu_markers if marker in body)
        
        if matches >= 2:
            print(f"{Fore.GREEN}EDU PORTAL ({matches} markers){Style.RESET_ALL}")
            return {
                'edu_portal': True,
                'edu_markers': matches,
                'telkom_compatible': True
            }
        else:
            print(f"{Fore.YELLOW}NOT EDU ({matches} markers){Style.RESET_ALL}")
            return {
                'edu_portal': False,
                'edu_markers': matches,
                'telkom_compatible': False
            }
            
    except Exception as e:
        print(f"{Fore.RED}ERROR{Style.RESET_ALL}")
        return {'edu_portal': False, 'error': str(e)}

# ============ STANDARD TESTS ============

def test_empty_sni(domain, timeout=5):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock) as ssock:
                return {'accepts_empty_sni': True, 'tls_version': ssock.version()}
    except:
        return {'accepts_empty_sni': False}

def test_wrong_sni(domain, wrong='google.com', timeout=5):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=wrong) as ssock:
                cert = ssock.getpeercert()
                sans = [s[1] for s in cert.get('subjectAltName', [])] if cert else []
                return {
                    'accepts_wrong_sni': True,
                    'wrong_sni_in_cert': wrong in str(sans),
                    'shared_hosting': wrong not in str(sans)
                }
    except:
        return {'accepts_wrong_sni': False}

def test_tls_versions(domain, timeout=5):
    versions = {}
    
    for v_name, min_v, max_v in [
        ('TLSv1.3', ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.MAXIMUM_SUPPORTED),
        ('TLSv1.2', ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
        ('TLSv1.1', ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
        ('TLSv1.0', ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
    ]:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = min_v
            if max_v != ssl.TLSVersion.MAXIMUM_SUPPORTED:
                context.maximum_version = max_v
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    versions[v_name] = True
        except:
            versions[v_name] = False
    
    legacy_score = 0
    if versions.get('TLSv1.0'):
        legacy_score = 20
    elif versions.get('TLSv1.1'):
        legacy_score = 15
    elif versions.get('TLSv1.2'):
        legacy_score = 5
    
    return {
        'versions': versions,
        'legacy_score': legacy_score,
        'supports_modern': versions.get('TLSv1.3') or versions.get('TLSv1.2')
    }

def test_cipher_suites(domain, timeout=5):
    all_ciphers = LEGACY_CIPHERS + MODERN_CIPHERS
    supported = []
    
    for cipher in all_ciphers:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers(cipher)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    supported.append(cipher)
        except:
            pass
    
    legacy_count = sum(1 for c in supported if c in LEGACY_CIPHERS)
    modern_count = sum(1 for c in supported if c in MODERN_CIPHERS)
    
    return {
        'supported_ciphers': supported,
        'legacy_count': legacy_count,
        'modern_count': modern_count,
        'has_legacy': legacy_count > 0,
        'legacy_score': legacy_count * 5
    }

# ============ UNIFIED SA TEST ============

def run_all_advanced_tests(domain, timeout=5, isp=''):
    """
    Run ALL advanced TLS tests with SA-specific checks
    """
    print(f"\n{Fore.CYAN}=== Advanced TLS: {domain} ==={Style.RESET_ALL}")
    if isp:
        print(f"{Fore.CYAN}ISP Profile: {isp.upper()}{Style.RESET_ALL}")
    
    results = {
        'domain': domain,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'isp': isp,
        'tests': {}
    }
    
    # Standard tests
    print(f"\n  {Fore.CYAN}Standard Tests:{Style.RESET_ALL}")
    
    print(f"    {Fore.YELLOW}Basic handshake...{Style.RESET_ALL}", end=' ')
    basic = test_tls_handshake(domain, timeout)
    if basic['success']:
        print(f"{Fore.GREEN}{basic['tls_version']} ({basic['response_time_ms']}ms){Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}FAILED{Style.RESET_ALL}")
        return {'score': 0, 'error': basic.get('error', 'TLS failed'), 'all_passed': False}
    
    time.sleep(0.3)
    
    print(f"    {Fore.YELLOW}Empty SNI...{Style.RESET_ALL}", end=' ')
    empty = test_empty_sni(domain, timeout)
    print(f"{Fore.GREEN if empty['accepts_empty_sni'] else Fore.RED}{'YES' if empty['accepts_empty_sni'] else 'NO'}{Style.RESET_ALL}")
    time.sleep(0.3)
    
    print(f"    {Fore.YELLOW}Wrong SNI...{Style.RESET_ALL}", end=' ')
    wrong = test_wrong_sni(domain, timeout)
    print(f"{Fore.GREEN if wrong['accepts_wrong_sni'] else Fore.RED}{'YES' if wrong['accepts_wrong_sni'] else 'NO'}{Style.RESET_ALL}")
    time.sleep(0.3)
    
    print(f"    {Fore.YELLOW}TLS versions...{Style.RESET_ALL}")
    versions = test_tls_versions(domain, timeout)
    for v, ok in versions['versions'].items():
        print(f"      {v}: {Fore.GREEN if ok else Fore.RED}{'✓' if ok else '✗'}{Style.RESET_ALL}")
    time.sleep(0.3)
    
    print(f"    {Fore.YELLOW}Cipher suites...{Style.RESET_ALL}")
    ciphers = test_cipher_suites(domain, timeout)
    print(f"      Legacy: {ciphers['legacy_count']}, Modern: {ciphers['modern_count']}")
    
    # SA-specific tests
    if isp:
        print(f"\n  {Fore.CYAN}SA-Specific Tests:{Style.RESET_ALL}")
        
        if isp.lower() == 'mtn':
            mtn = test_mtn_tunnel_detection(domain, timeout)
            results['tests']['mtn_tunnel'] = mtn
            time.sleep(0.3)
        
        elif isp.lower() == 'vodacom':
            voda = test_vodacom_strict_sni(domain, timeout)
            results['tests']['vodacom_sni'] = voda
            time.sleep(0.3)
        
        elif isp.lower() == 'telkom':
            telkom = test_telkom_edu_portal(domain, timeout)
            results['tests']['telkom_edu'] = telkom
            time.sleep(0.3)
        
        elif isp.lower() in ['cell_c', 'cellc']:
            # Cell C similar to Vodacom but less strict
            voda = test_vodacom_strict_sni(domain, timeout)
            results['tests']['cellc_sni'] = voda
            time.sleep(0.3)
    
    # Calculate exploitability score
    exploitability = 0
    reasons = []
    
    if basic['success']:
        exploitability += 20
        reasons.append("TLS OK")
        
        if basic['tls_version'] == 'TLSv1.3':
            exploitability += 10
        elif basic['tls_version'] == 'TLSv1.2':
            exploitability += 5
        
        if basic['response_time_ms'] < 100:
            exploitability += 5
    
    if empty['accepts_empty_sni']:
        exploitability += 15
        reasons.append("Empty SNI")
    
    if wrong['accepts_wrong_sni']:
        exploitability += 10
        reasons.append("Wrong SNI")
        if wrong.get('shared_hosting'):
            exploitability += 5
            reasons.append("Shared hosting")
    
    legacy = versions.get('legacy_score', 0)
    exploitability += legacy
    if legacy > 0:
        reasons.append(f"Legacy TLS (+{legacy})")
    
    cipher_legacy = ciphers.get('legacy_score', 0)
    exploitability += cipher_legacy
    
    # SA-specific adjustments
    if isp:
        if isp.lower() == 'mtn':
            mtn_test = results['tests'].get('mtn_tunnel', {})
            if not mtn_test.get('looks_clean', True):
                exploitability -= 20
                reasons.append("MTN tunnel risk (-20)")
        
        elif isp.lower() == 'vodacom':
            voda_test = results['tests'].get('vodacom_sni', {})
            if voda_test.get('vodacom_compatible') is False:
                exploitability -= 15
                reasons.append("Vodacom SNI strict (-15)")
        
        elif isp.lower() == 'telkom':
            telkom_test = results['tests'].get('telkom_edu', {})
            if telkom_test.get('telkom_compatible') is True:
                exploitability += 10
                reasons.append("Telkom edu compatible (+10)")
    
    exploitability = max(0, min(100, exploitability))
    
    results['exploitability_score'] = exploitability
    results['exploitability_reasons'] = reasons
    
    # Summary
    print(f"\n{Fore.GREEN}=== Results ==={Style.RESET_ALL}")
    print(f"  Empty SNI: {'✅' if empty['accepts_empty_sni'] else '❌'}")
    print(f"  Wrong SNI: {'✅' if wrong['accepts_wrong_sni'] else '❌'}")
    print(f"  Legacy TLS: {versions['legacy_score']} pts")
    print(f"  Legacy Ciphers: {ciphers['legacy_count']}")
    
    if isp:
        if isp.lower() == 'mtn':
            mtn = results['tests'].get('mtn_tunnel', {})
            print(f"  MTN Clean: {'✅' if mtn.get('looks_clean') else '❌'}")
        elif isp.lower() == 'vodacom':
            voda = results['tests'].get('vodacom_sni', {})
            print(f"  Vodacom Compatible: {'✅' if voda.get('vodacom_compatible') else '❌'}")
        elif isp.lower() == 'telkom':
            telkom = results['tests'].get('telkom_edu', {})
            print(f"  Telkom Edu: {'✅' if telkom.get('telkom_compatible') else '❌'}")
    
    score_color = Fore.GREEN if exploitability >= 50 else Fore.YELLOW if exploitability >= 25 else Fore.RED
    print(f"\n{score_color}Exploitability: {exploitability}/100{Style.RESET_ALL}")
    
    return results

# ============ MAIN ============

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SA Advanced TLS Tests{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Single domain")
    print("2. Batch test")
    
    choice = input("\nChoice (1-2): ").strip()
    
    isp = input("Your ISP (MTN/Vodacom/Telkom/Cell C): ").strip()
    
    if choice == '1':
        domain = input("Domain: ").strip().lower()
        if not domain:
            print(f"{Fore.RED}No domain{Style.RESET_ALL}")
            return
        
        results = run_all_advanced_tests(domain, isp=isp)
        
        save = input("Save? (y/n): ").strip().lower()
        if save == 'y':
            filename = f"sa_tls_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(RESULTS_DIR, filename)
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}Saved: {filepath}{Style.RESET_ALL}")
    
    elif choice == '2':
        print("Enter domains (one per line, empty to finish):")
        domains = []
        while True:
            line = input().strip().lower()
            if not line:
                break
            domains.append(line)
        
        if not domains:
            print(f"{Fore.RED}No domains{Style.RESET_ALL}")
            return
        
        all_results = []
        for i, domain in enumerate(domains, 1):
            print(f"\n{Fore.CYAN}[{i}/{len(domains)}]{Style.RESET_ALL}")
            try:
                result = run_all_advanced_tests(domain, isp=isp)
                all_results.append(result)
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            time.sleep(1)
        
        save = input("\nSave all? (y/n): ").strip().lower()
        if save == 'y':
            filename = f"sa_tls_batch_{time.strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(RESULTS_DIR, filename)
            with open(filepath, 'w') as f:
                json.dump(all_results, f, indent=2, default=str)
            print(f"{Fore.GREEN}Saved: {filepath}{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

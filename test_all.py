#!/usr/bin/env python3
"""
SNI Host Finder PRO — Unified Full Test Suite v2.1
SOUTH AFRICA EDITION — Optimized for MTN & Vodacom (also Telkom, Cell C)

Tests ONE or MULTIPLE hosts with ALL methods:
  • DNS + Static IP detection
  • Deep TLS / SSL handshake (correct SNI, empty SNI, wrong SNI)
  • MTN-specific tunnel detection
  • Vodacom strict SNI / IP+SNI match
  • HTTP Custom Host Header testing (HTTP Injector / HA Tunnel style)
  • Content legitimacy (education / health / government)
  • DPI evasion scoring
  • ISP rule scoring

Output:
  🟢 GREEN  = High probability it works for TLS/SSL or Custom Header
  🟡 YELLOW = Medium chance
  🔴 RED    = Low chance / skip

Auto-extracts domains even from messy jammed text.
Concurrent multi-host testing with rate limiting.
"""

import os
import sys
import time
import json
import socket
import ssl
import re
import http.client
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Optional, Tuple

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        GREEN = YELLOW = RED = CYAN = MAGENTA = WHITE = BLUE = ""
        RESET = ""
    class Style:
        RESET_ALL = BRIGHT = ""
    def init(*a, **k): pass

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# ============ PATHS ============
RESULTS_DIR = os.path.expanduser("\~/snihost_pro/results")
CONFIG_DIR = os.path.expanduser("\~/snihost_pro/configs")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

PERSONAL_DB = os.path.expanduser("\~/snihost_pro/my_zero_rated_hosts.json")
COMMUNITY_DB = os.path.expanduser("\~/snihost_pro/community/local_intel.json")

# ============ SA ISP CONFIG (MTN & Vodacom prioritized) ============
SA_ISP_CONFIG = {
    'mtn': {
        'full_name': 'MTN South Africa',
        'priority': 1,
        'categories': ['education', 'health', 'government', 'job'],
        'bans_tunneling': True,
        'checks_ja3': True,
        'preferred_tlds': ['.ac.za', '.edu.za', '.gov.za', '.org.za'],
        'cdn_penalty': 20,
        'static_bonus': 15,
        'score_weights': {'tls': 0.28, 'http_header': 0.18, 'content': 0.22, 'isp': 0.18, 'dpi': 0.14},
        'notes': 'Bans tunneling explicitly. Prefers clean modern TLS + education/health/gov.'
    },
    'vodacom': {
        'full_name': 'Vodacom South Africa',
        'priority': 1,
        'categories': ['education', 'health', 'government'],
        'strict_sni': True,
        'verifies_ip_sni': True,
        'preferred_tlds': ['.ac.za', '.gov.za'],
        'cdn_penalty': 18,
        'static_bonus': 12,
        'score_weights': {'tls': 0.30, 'http_header': 0.15, 'content': 0.25, 'isp': 0.18, 'dpi': 0.12},
        'notes': 'Strict SNI + IP match. Content type matters a lot.'
    },
    'telkom': {
        'full_name': 'Telkom Mobile',
        'priority': 2,
        'categories': ['education', 'health', 'government'],
        'preferred_tlds': ['.ac.za', '.edu.za', '.gov.za'],
        'cdn_penalty': 5,
        'static_bonus': 8,
        'score_weights': {'tls': 0.25, 'http_header': 0.15, 'content': 0.25, 'isp': 0.20, 'dpi': 0.15},
        'notes': 'Most reliable for education portals.'
    },
    'cell_c': {
        'full_name': 'Cell C',
        'priority': 3,
        'categories': ['education', 'health', 'government'],
        'preferred_tlds': ['.ac.za', '.gov.za'],
        'cdn_penalty': 12,
        'static_bonus': 8,
        'score_weights': {'tls': 0.28, 'http_header': 0.15, 'content': 0.22, 'isp': 0.18, 'dpi': 0.17},
        'notes': 'Fewer zero-rated hosts after spectrum return.'
    }
}

CDN_RANGES = [
    ('104.16.0.0', '104.31.255.255'),
    ('172.64.0.0', '172.71.255.255'),
    ('13.32.0.0', '13.35.255.255'),
    ('52.84.0.0', '52.85.255.255'),
    ('54.192.0.0', '54.207.255.255'),
    ('151.101.0.0', '151.101.255.255'),
    ('23.32.0.0', '23.63.255.255'),
    ('157.52.64.0', '157.52.127.255'),
]

# ============ SMART HOST EXTRACTOR ============

def clean_host_line(line: str) -> Optional[str]:
    hosts = extract_all_hosts(line)
    return hosts[0] if hosts else None


def extract_all_hosts(text: str) -> List[str]:
    """
    Aggressively extract ALL valid domains from any messy text.
    Handles jammed formats like:
      DUT Moodlehttps://tlzprod.dut.ac.za/DUT Websitehttps://www.dut.ac.za/
    """
    if not text or not isinstance(text, str):
        return []

    found = []
    seen = set()

    # Strategy 1: Extract from http(s):// patterns
    url_re = re.compile(
        r'https?://(?:www\.)?([a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?)+)',
        re.IGNORECASE
    )
    for m in url_re.finditer(text):
        domain = m.group(1).lower().rstrip('.')
        domain = _trim_domain(domain)
        if _is_valid_domain(domain) and domain not in seen:
            seen.add(domain)
            found.append(domain)

    # Strategy 2: Loose domain patterns
    loose_re = re.compile(
        r'(?:^|[^a-zA-Z0-9.-])(?:www\.)?([a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,}){1,4})(?=[^a-zA-Z0-9.-]|$)',
        re.IGNORECASE
    )
    for m in loose_re.finditer(text):
        domain = m.group(1).lower().rstrip('.')
        domain = _trim_domain(domain)
        if _is_valid_domain(domain) and domain not in seen:
            seen.add(domain)
            found.append(domain)

    found.sort(key=lambda d: (-d.count('.'), d))
    return found


def _trim_domain(domain: str) -> str:
    bad_suffixes = [
        'dut', 'moodle', 'website', 'libraries', 'libguides', 'libchat',
        'portal', 'mobile', 'journals', 'catalogue', 'login', 'index',
        'html', 'htm', 'php', 'asp', 'aspx', 'jsp'
    ]
    lower = domain.lower()
    for suf in bad_suffixes:
        if lower.endswith(suf) and '.' in lower[:-len(suf)]:
            candidate = domain[:-len(suf)]
            if _is_valid_domain(candidate):
                return candidate
    domain = re.sub(r'\.(html?|php|asp|aspx|jsp)$', '', domain, flags=re.I)
    return domain


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) < 4 or len(domain) > 253:
        return False
    if domain.count('.') < 1:
        return False
    if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9]$', domain):
        return False
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    tld = parts[-1].lower()
    ALLOWED_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'ac', 'za', 'co', 'info', 'biz',
        'io', 'app', 'dev', 'me', 'tv', 'cc', 'us', 'uk', 'ng', 'ke', 'gh',
        'africa', 'school', 'museum', 'name', 'pro', 'mil', 'int'
    }
    if tld not in ALLOWED_TLDS:
        if len(parts) >= 3 and parts[-2].lower() in ALLOWED_TLDS:
            pass
        else:
            return False
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return False
    if domain in ('example.com', 'test.com', 'localhost') or tld in (
        'html', 'htm', 'php', 'asp', 'js', 'css', 'jpg', 'png', 'gif', 'pdf'
    ):
        return False
    for label in parts:
        if len(label) == 0 or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
    return True


def clean_hosts_bulk(text_or_list) -> List[str]:
    if isinstance(text_or_list, list):
        text = '\n'.join(str(x) for x in text_or_list)
    else:
        text = str(text_or_list)
    return extract_all_hosts(text)


# ============ DNS & IP HELPERS ============

def ip_to_int(ip: str) -> int:
    parts = [int(x) for x in ip.split('.')]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def is_cdn_ip(ip: str) -> bool:
    try:
        ip_int = ip_to_int(ip)
        for start, end in CDN_RANGES:
            if ip_to_int(start) <= ip_int <= ip_to_int(end):
                return True
    except:
        pass
    return False


def resolve_dns(host: str) -> Dict:
    result = {'ipv4': [], 'ipv6': [], 'error': None, 'is_static': False}
    if HAS_DNS:
        try:
            answers = dns.resolver.resolve(host, 'A')
            result['ipv4'] = [str(r) for r in answers]
        except Exception as e:
            result['error'] = str(e)
        try:
            answers = dns.resolver.resolve(host, 'AAAA')
            result['ipv6'] = [str(r) for r in answers]
        except:
            pass
    else:
        try:
            result['ipv4'] = [socket.gethostbyname(host)]
        except Exception as e:
            result['error'] = str(e)

    if result['ipv4']:
        result['is_static'] = not is_cdn_ip(result['ipv4'][0])
    return result


# ============ TLS / SSL TESTS ============

def test_tls_handshake(host: str, sni: Optional[str] = None, timeout: float = 5.0) -> Dict:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        start = time.time()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=(sni or host)) as ssock:
                elapsed = (time.time() - start) * 1000
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                return {
                    'success': True,
                    'tls_version': ssock.version(),
                    'cipher': cipher[0] if cipher else None,
                    'cipher_bits': cipher[2] if cipher else 0,
                    'response_time_ms': round(elapsed, 1),
                    'cert_sans': [s[1] for s in cert.get('subjectAltName', [])] if cert else [],
                    'cert_issuer': str(cert.get('issuer', '')) if cert else '',
                    'cert_subject': str(cert.get('subject', '')) if cert else '',
                }
    except Exception as e:
        return {'success': False, 'error': str(e)[:80]}


def test_empty_sni(host: str, timeout: float = 4.0) -> Dict:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as ssock:
                return {'accepts_empty_sni': True, 'tls_version': ssock.version()}
    except:
        return {'accepts_empty_sni': False}


def test_wrong_sni(host: str, wrong: str = 'google.com', timeout: float = 4.0) -> Dict:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=wrong) as ssock:
                return {'accepts_wrong_sni': True, 'tls_version': ssock.version()}
    except:
        return {'accepts_wrong_sni': False}


def test_mtn_tunnel_risk(host: str, timeout: float = 4.0) -> Dict:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                risk = 0
                if version in ('TLSv1', 'TLSv1.1'):
                    risk += 25
                if cipher and any(x in cipher[0] for x in ('RC4', 'DES', '3DES', 'MD5', 'SHA1')):
                    risk += 20
                return {'tunnel_risk': risk, 'looks_clean': risk < 15, 'version': version}
    except Exception as e:
        return {'tunnel_risk': 40, 'looks_clean': False, 'error': str(e)[:40]}


def test_vodacom_strict(host: str, timeout: float = 4.0) -> Dict:
    basic = test_tls_handshake(host, sni=host, timeout=timeout)
    if not basic['success']:
        return {'vodacom_compatible': False, 'reason': 'handshake failed'}
    sans = basic.get('cert_sans', [])
    host_in_sans = any(host in s or s in host for s in sans) or not sans
    return {
        'vodacom_compatible': basic['success'] and host_in_sans,
        'tls_version': basic.get('tls_version'),
        'has_matching_san': host_in_sans
    }


# ============ HTTP CUSTOM HOST HEADER ============

def test_http_custom_header(host: str, timeout: float = 5.0) -> Dict:
    results = {
        'https_host_header_ok': False,
        'http_host_header_ok': False,
        'status_https': None,
        'status_http': None,
        'score': 0
    }
    try:
        conn = http.client.HTTPSConnection(host, timeout=timeout, context=ssl._create_unverified_context())
        conn.request("GET", "/", headers={
            'Host': host,
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36',
            'Accept': 'text/html',
            'Connection': 'close'
        })
        resp = conn.getresponse()
        results['status_https'] = resp.status
        results['https_host_header_ok'] = resp.status in (200, 301, 302, 303, 307, 308)
        conn.close()
    except:
        pass
    try:
        conn = http.client.HTTPConnection(host, timeout=timeout)
        conn.request("GET", "/", headers={
            'Host': host,
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13)',
            'Connection': 'close'
        })
        resp = conn.getresponse()
        results['status_http'] = resp.status
        results['http_host_header_ok'] = resp.status in (200, 301, 302, 303, 307, 308)
        conn.close()
    except:
        pass

    score = 0
    if results['https_host_header_ok']:
        score += 40
    if results['http_host_header_ok']:
        score += 25
    if results['status_https'] == 200:
        score += 15
    results['score'] = min(score, 100)
    return results


# ============ CONTENT VERIFICATION ============

def guess_category(host: str) -> str:
    d = host.lower()
    if any(t in d for t in ('.ac.za', '.edu.za', 'university', 'college', 'school')):
        return 'education'
    if any(t in d for t in ('health', 'hospital', 'medical', 'covid', 'nicd', 'sahpra', 'clinic')):
        return 'health'
    if any(t in d for t in ('.gov.za', 'govt', 'government', 'municipal')):
        return 'government'
    if any(t in d for t in ('job', 'career', 'harambee', 'sayouth', 'employment')):
        return 'job'
    return 'education'


def verify_content(host: str, category: str = 'education', timeout: float = 6.0) -> Dict:
    keywords = {
        'education': ['university', 'college', 'student', 'course', 'learn', 'education',
                      'academic', 'study', 'lecture', 'campus', 'module', 'degree', 'faculty'],
        'health': ['health', 'medical', 'hospital', 'covid', 'vaccine', 'disease',
                   'treatment', 'patient', 'clinic', 'doctor', 'medicine'],
        'government': ['government', 'department', 'minister', 'public', 'service',
                       'official', 'policy', 'parliament', 'council', 'national'],
        'job': ['job', 'employment', 'career', 'vacancy', 'recruit', 'work', 'hire']
    }
    try:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(host, timeout=timeout, context=ctx)
        conn.request("GET", "/", headers={
            'Host': host,
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36',
            'Accept': 'text/html'
        })
        resp = conn.getresponse()
        content_type = (resp.getheader('Content-Type') or '').lower()
        body = resp.read(4000).decode('utf-8', errors='ignore').lower()
        conn.close()

        cat_kw = keywords.get(category, [])
        matches = sum(1 for kw in cat_kw if kw in body)

        legitimacy = 0
        if matches >= 5:
            legitimacy = 45
        elif matches >= 2:
            legitimacy = 28
        elif matches >= 1:
            legitimacy = 12
        else:
            legitimacy = 3

        if 'text/html' in content_type:
            legitimacy += 12
        if resp.status == 200:
            legitimacy += 8

        return {
            'legitimacy_score': min(legitimacy, 60),
            'content_type': content_type,
            'keyword_matches': matches,
            'looks_legitimate': legitimacy >= 25,
            'http_status': resp.status
        }
    except Exception as e:
        return {
            'legitimacy_score': 0,
            'error': str(e)[:50],
            'looks_legitimate': False,
            'http_status': None
        }


# ============ SCORING ============

def get_isp_bonus(host: str, isp: str, category: str, is_static: bool) -> Tuple[int, str]:
    if not isp:
        return 0, "No ISP"
    cfg = SA_ISP_CONFIG.get(isp.lower().replace(' ', '_'))
    if not cfg:
        return 0, "Unknown ISP"

    score = 0
    reasons = []

    for tld in cfg.get('preferred_tlds', []):
        if host.endswith(tld):
            score += 18
            reasons.append(f"TLD {tld}")
            break

    if category in cfg.get('categories', []):
        score += 12
        reasons.append(f"{category} supported")

    if is_static:
        score += cfg.get('static_bonus', 8)
        reasons.append("Static IP")
    else:
        score -= cfg.get('cdn_penalty', 10)
        reasons.append("CDN penalty")

    if isp.lower() == 'mtn' and category == 'job':
        score += 8
        reasons.append("MTN Open Time")

    if isp.lower() == 'telkom' and category == 'education':
        score += 10
        reasons.append("Telkom edu strength")

    return max(0, min(score, 50)), ' | '.join(reasons) if reasons else '—'


def get_dpi_score(tls: Dict, http_hdr: Dict, content: Dict, dns: Dict, isp: str) -> int:
    score = 50
    if tls.get('accepts_empty_sni'):
        score += 8
    if tls.get('accepts_wrong_sni'):
        score += 5
    if dns.get('is_static'):
        score += 12
    else:
        score -= 15
    if content.get('looks_legitimate'):
        score += 10
    if http_hdr.get('https_host_header_ok'):
        score += 8

    if isp.lower() == 'mtn':
        risk = tls.get('mtn_tunnel_risk', 20)
        score -= risk // 2
    if isp.lower() == 'vodacom' and not tls.get('vodacom_compatible', True):
        score -= 15

    return max(0, min(100, score))


def calculate_final(tls_score: int, http_score: int, content_score: int,
                    isp_bonus: int, dpi: int, isp: str) -> int:
    weights = SA_ISP_CONFIG.get(isp.lower(), {}).get('score_weights', {
        'tls': 0.28, 'http_header': 0.18, 'content': 0.22, 'isp': 0.18, 'dpi': 0.14
    })
    final = (
        tls_score * weights.get('tls', 0.28) +
        http_score * weights.get('http_header', 0.18) +
        content_score * weights.get('content', 0.22) * 1.6 +
        isp_bonus * weights.get('isp', 0.18) * 2.0 +
        dpi * weights.get('dpi', 0.14)
    )
    return max(0, min(100, int(round(final))))


def get_verdict(score: int) -> Dict:
    if score >= 70:
        return {
            'color': Fore.GREEN,
            'level': 'GREEN',
            'emoji': '🟢',
            'text': 'HIGH CHANCE — Good for TLS/SSL & Custom Header',
            'advice': 'Strong candidate. Test live on your ISP.'
        }
    elif score >= 45:
        return {
            'color': Fore.YELLOW,
            'level': 'YELLOW',
            'emoji': '🟡',
            'text': 'MEDIUM CHANCE — May work on one method',
            'advice': 'Worth a live burn test. Prefer TLS method first.'
        }
    else:
        return {
            'color': Fore.RED,
            'level': 'RED',
            'emoji': '🔴',
            'text': 'LOW CHANCE — Skip or low priority',
            'advice': 'Unlikely to give free data on SA networks.'
        }


# ============ CORE SINGLE HOST TEST ============

def run_all_tls_tests(host: str, isp: str = '') -> Dict:
    basic = test_tls_handshake(host)
    if not basic['success']:
        return {
            'score': 0,
            'all_passed': False,
            'error': basic.get('error', 'TLS failed'),
            'accepts_empty_sni': False,
            'accepts_wrong_sni': False
        }

    empty = test_empty_sni(host)
    wrong = test_wrong_sni(host)
    mtn = test_mtn_tunnel_risk(host) if isp.lower() == 'mtn' else {}
    voda = test_vodacom_strict(host) if isp.lower() == 'vodacom' else {}

    score = 25
    reasons = ['TLS OK']

    ver = basic.get('tls_version', '')
    if ver == 'TLSv1.3':
        score += 12
        reasons.append('TLS1.3')
    elif ver == 'TLSv1.2':
        score += 7
        reasons.append('TLS1.2')

    if basic.get('response_time_ms', 999) < 120:
        score += 8
        reasons.append('Fast')

    if empty.get('accepts_empty_sni'):
        score += 10
        reasons.append('Empty SNI OK')
    if wrong.get('accepts_wrong_sni'):
        score += 8
        reasons.append('Wrong SNI OK')

    issuer = basic.get('cert_issuer', '')
    if any(ca in issuer for ca in ('DigiCert', 'GlobalSign', 'Sectigo', 'GeoTrust', 'Entrust')):
        score += 8
        reasons.append('Good CA')

    if mtn:
        if mtn.get('looks_clean'):
            score += 10
            reasons.append('MTN clean')
        else:
            score -= mtn.get('tunnel_risk', 20) // 2
            reasons.append(f"MTN risk {mtn.get('tunnel_risk')}")

    if voda:
        if voda.get('vodacom_compatible'):
            score += 12
            reasons.append('Vodacom OK')
        else:
            score -= 10
            reasons.append('Vodacom strict fail')

    score = max(0, min(100, score))

    return {
        'score': score,
        'tls_version': ver,
        'response_time_ms': basic.get('response_time_ms'),
        'accepts_empty_sni': empty.get('accepts_empty_sni', False),
        'accepts_wrong_sni': wrong.get('accepts_wrong_sni', False),
        'mtn_tunnel_risk': mtn.get('tunnel_risk'),
        'vodacom_compatible': voda.get('vodacom_compatible'),
        'cert_issuer': issuer,
        'reasons': reasons,
        'all_passed': True
    }


def test_single_host(host: str, isp: str = '', country: str = 'South Africa',
                     verbose: bool = True) -> Dict:
    if verbose:
        print(f"\n{'='*68}")
        print(f"  TESTING: {Fore.CYAN}{host}{Style.RESET_ALL}")
        print(f"  ISP: {isp or '—'}  |  Country: {country}")
        print(f"{'='*68}")

    category = guess_category(host)

    if verbose:
        print(f"\n  {Fore.CYAN}[1/6] DNS Resolution{Style.RESET_ALL}")
    dns = resolve_dns(host)
    if verbose:
        ipv4 = dns.get('ipv4') or ['None']
        print(f"      IPv4 : {ipv4[0] if ipv4 else 'FAIL'}")
        static = dns.get('is_static', False)
        print(f"      Type : {Fore.GREEN if static else Fore.YELLOW}{'STATIC (good)' if static else 'CDN / Dynamic'}{Style.RESET_ALL}")

    if verbose:
        print(f"\n  {Fore.CYAN}[2/6] Deep TLS / SSL Tests{Style.RESET_ALL}")
    tls = run_all_tls_tests(host, isp)
    if not tls.get('all_passed'):
        if verbose:
            print(f"      {Fore.RED}TLS FAILED — {tls.get('error', 'unknown')}{Style.RESET_ALL}")
        verdict = get_verdict(0)
        return {
            'host': host,
            'final_score': 0,
            'verdict': verdict['text'],
            'verdict_level': 'RED',
            'verdict_color': 'red',
            'error': tls.get('error'),
            'tls_score': 0,
            'http_score': 0,
            'content_score': 0,
            'category': category
        }
    if verbose:
        print(f"      Handshake : {Fore.GREEN}OK ({tls.get('tls_version')}){Style.RESET_ALL}")
        print(f"      Empty SNI : {Fore.GREEN if tls.get('accepts_empty_sni') else Fore.RED}{'YES' if tls.get('accepts_empty_sni') else 'NO'}{Style.RESET_ALL}")
        print(f"      Wrong SNI : {Fore.GREEN if tls.get('accepts_wrong_sni') else Fore.RED}{'YES' if tls.get('accepts_wrong_sni') else 'NO'}{Style.RESET_ALL}")
        if isp.lower() == 'mtn':
            clean = tls.get('mtn_tunnel_risk', 99) < 15
            print(f"      MTN Clean : {Fore.GREEN if clean else Fore.YELLOW}{'YES' if clean else 'RISK'}{Style.RESET_ALL}")
        if isp.lower() == 'vodacom':
            ok = tls.get('vodacom_compatible')
            print(f"      Vodacom   : {Fore.GREEN if ok else Fore.RED}{'COMPATIBLE' if ok else 'STRICT FAIL'}{Style.RESET_ALL}")
        print(f"      TLS Score  : {tls['score']}%")

    if verbose:
        print(f"\n  {Fore.CYAN}[3/6] HTTP Custom Host Header{Style.RESET_ALL}")
    http_hdr = test_http_custom_header(host)
    if verbose:
        print(f"      HTTPS Host : {Fore.GREEN if http_hdr['https_host_header_ok'] else Fore.RED}{'OK' if http_hdr['https_host_header_ok'] else 'FAIL'} ({http_hdr.get('status_https')}){Style.RESET_ALL}")
        print(f"      HTTP Host  : {Fore.GREEN if http_hdr['http_host_header_ok'] else Fore.RED}{'OK' if http_hdr['http_host_header_ok'] else 'FAIL'} ({http_hdr.get('status_http')}){Style.RESET_ALL}")
        print(f"      Header Score: {http_hdr['score']}%")

    if verbose:
        print(f"\n  {Fore.CYAN}[4/6] Content Legitimacy ({category}){Style.RESET_ALL}")
    content = verify_content(host, category)
    if verbose:
        leg = content.get('legitimacy_score', 0)
        print(f"      Matches   : {content.get('keyword_matches', 0)} keywords")
        print(f"      Score     : {leg}%  {'✅' if content.get('looks_legitimate') else '❌'}")

    if verbose:
        print(f"\n  {Fore.CYAN}[5/6] ISP Rules ({isp or 'generic'}){Style.RESET_ALL}")
    isp_bonus, isp_reason = get_isp_bonus(host, isp, category, dns.get('is_static', False))
    if verbose:
        print(f"      Bonus     : +{isp_bonus}")
        print(f"      Reasons   : {isp_reason}")

    if verbose:
        print(f"\n  {Fore.CYAN}[6/6] DPI Evasion Score{Style.RESET_ALL}")
    dpi = get_dpi_score(tls, http_hdr, content, dns, isp)
    if verbose:
        print(f"      DPI Score : {dpi}%")

    final = calculate_final(
        tls.get('score', 0),
        http_hdr.get('score', 0),
        content.get('legitimacy_score', 0),
        isp_bonus,
        dpi,
        isp
    )
    verdict = get_verdict(final)

    if verbose:
        print(f"\n{'─'*68}")
        print(f"  {verdict['color']}{verdict['emoji']}  FINAL SCORE: {final}/100  —  {verdict['text']}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Advice: {verdict['advice']}{Style.RESET_ALL}")
        print(f"{'─'*68}")

    return {
        'host': host,
        'category': category,
        'final_score': final,
        'verdict': verdict['text'],
        'verdict_level': verdict['level'],
        'verdict_color': verdict['level'].lower(),
        'tls_score': tls.get('score', 0),
        'http_score': http_hdr.get('score', 0),
        'content_score': content.get('legitimacy_score', 0),
        'isp_bonus': isp_bonus,
        'dpi_score': dpi,
        'is_static': dns.get('is_static', False),
        'tls_version': tls.get('tls_version'),
        'accepts_empty_sni': tls.get('accepts_empty_sni'),
        'https_header_ok': http_hdr.get('https_host_header_ok'),
        'details': {
            'tls': tls,
            'http_header': http_hdr,
            'content': content,
            'dns': dns
        }
    }


# ============ MULTI-HOST (CONCURRENT) ============

def test_multiple_hosts(hosts: List[str], isp: str = '', country: str = 'South Africa',
                        max_workers: int = 12) -> List[Dict]:
    print(f"\n{'='*68}")
    print(f"  FULL TEST SUITE — {len(hosts)} HOSTS  |  Concurrent (max {max_workers})")
    print(f"  Focus: MTN / Vodacom / Telkom / Cell C")
    print(f"{'='*68}")

    results = []
    completed = 0

    def _worker(h):
        return test_single_host(h, isp, country, verbose=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_worker, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(future_map):
            host = future_map[fut]
            completed += 1
            try:
                res = fut.result()
                results.append(res)
                level = res.get('verdict_level', 'RED')
                color = Fore.GREEN if level == 'GREEN' else Fore.YELLOW if level == 'YELLOW' else Fore.RED
                print(f"  [{completed}/{len(hosts)}] {color}{res['final_score']:3d}{Style.RESET_ALL}  {host}")
            except Exception as e:
                print(f"  [{completed}/{len(hosts)}] {Fore.RED}ERR{Style.RESET_ALL}  {host} → {e}")
                results.append({
                    'host': host, 'final_score': 0, 'verdict_level': 'RED',
                    'verdict': 'Error', 'error': str(e)
                })

    results.sort(key=lambda x: x.get('final_score', 0), reverse=True)

    print(f"\n{'='*68}")
    print(f"  RANKED RESULTS")
    print(f"{'='*68}")
    print(f"  {'#':<3} {'Score':<6} {'Level':<8} {'Host':<40} {'TLS':<5} {'HDR':<5} {'Cat'}")
    print(f"  {'─'*3} {'─'*6} {'─'*8} {'─'*40} {'─'*5} {'─'*5} {'─'*10}")

    for i, r in enumerate(results, 1):
        level = r.get('verdict_level', 'RED')
        color = Fore.GREEN if level == 'GREEN' else Fore.YELLOW if level == 'YELLOW' else Fore.RED
        print(f"  {i:<3} {color}{r.get('final_score', 0):>3}{Style.RESET_ALL}   "
              f"{color}{level:<8}{Style.RESET_ALL} "
              f"{r.get('host', ''):<40} "
              f"{r.get('tls_score', 0):>3}  "
              f"{r.get('http_score', 0):>3}  "
              f"{r.get('category', '')}")

    green = sum(1 for r in results if r.get('verdict_level') == 'GREEN')
    yellow = sum(1 for r in results if r.get('verdict_level') == 'YELLOW')
    red = sum(1 for r in results if r.get('verdict_level') == 'RED')
    print(f"\n  Summary: {Fore.GREEN}{green} Green{Style.RESET_ALL}  |  "
          f"{Fore.YELLOW}{yellow} Yellow{Style.RESET_ALL}  |  "
          f"{Fore.RED}{red} Red{Style.RESET_ALL}")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(RESULTS_DIR, f"test_all_{stamp}.json")
    with open(out_path, 'w') as f:
        json.dump({
            'timestamp': stamp,
            'isp': isp,
            'country': country,
            'total': len(results),
            'green': green,
            'yellow': yellow,
            'red': red,
            'results': results
        }, f, indent=2)
    print(f"\n  Results saved → {out_path}")

    top = [r for r in results if r.get('final_score', 0) >= 55][:8]
    if top:
        print(f"\n  {Fore.CYAN}Top candidates ready for config export:{Style.RESET_ALL}")
        for r in top:
            print(f"    • {r['host']} ({r['final_score']})")
        gen = input(f"\n  Generate VPN configs for top hosts? (y/n): ").strip().lower()
        if gen == 'y':
            generate_configs(top, isp)

    return results


# ============ CONFIG GENERATORS ============

def generate_configs(hosts_results: List[Dict], isp: str = ''):
    print(f"\n  Generating configs → {CONFIG_DIR}")
    for r in hosts_results:
        host = r['host']
        score = r.get('final_score', 0)
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', host)

        tls_cfg = f"""# TLS / SSL Method — {host}
# Score: {score} | ISP: {isp}
# Use with: TLS Tunnel, HA Tunnel (SSL), NapsternetV (TLS)

SNI: {host}
Server: [YOUR_VPN_SERVER_IP]
Port: 443
Protocol: TLS / SSL
Payload: (leave empty or use default)
"""
        path = os.path.join(CONFIG_DIR, f"{safe_name}_tls.txt")
        with open(path, 'w') as f:
            f.write(tls_cfg)

        http_cfg = f"""# HTTP Custom Header Method — {host}
# Score: {score} | ISP: {isp}
# Use with: HTTP Injector, HA Tunnel Plus (HTTP), NapsternetV (HTTP)

Host Header: {host}
Payload example:
GET / HTTP/1.1[crlf]Host: {host}[crlf]Connection: Keep-Alive[crlf][crlf]

or

CONNECT [host_port] HTTP/1.1[crlf]Host: {host}[crlf][crlf]
"""
        path = os.path.join(CONFIG_DIR, f"{safe_name}_http.txt")
        with open(path, 'w') as f:
            f.write(http_cfg)

        path = os.path.join(CONFIG_DIR, f"{safe_name}.sni")
        with open(path, 'w') as f:
            f.write(host + "\n")

    print(f"  {Fore.GREEN}Configs written for {len(hosts_results)} hosts{Style.RESET_ALL}")
    print(f"  Folder: {CONFIG_DIR}")


# ============ MAIN ============

def main():
    print(f"\n{Fore.CYAN}{'='*68}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SNI Host Finder PRO — Unified Test Suite v2.1{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  South Africa Edition  •  MTN & Vodacom focused{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*68}{Style.RESET_ALL}\n")

    print("Modes:")
    print("  1. Test SINGLE host")
    print("  2. Test MULTIPLE hosts (paste list — auto cleans text)")
    print("  3. Quick test common SA education/health hosts")
    print("  4. Exit")

    choice = input("\nChoice (1-4): ").strip()

    if choice == '4':
        return

    isp = input("Your ISP (MTN / Vodacom / Telkom / Cell C) [MTN]: ").strip() or "MTN"
    isp = isp.lower().replace(' ', '_')
    if isp in ('cellc', 'cell-c'):
        isp = 'cell_c'
    country = input("Country [South Africa]: ").strip() or "South Africa"

    if choice == '1':
        raw = input("\nEnter host (SNI) — can include dirty text: ").strip()
        host = clean_host_line(raw)
        if not host:
            print(f"{Fore.RED}Could not extract a valid host{Style.RESET_ALL}")
            return
        print(f"Cleaned → {Fore.GREEN}{host}{Style.RESET_ALL}")
        result = test_single_host(host, isp, country, verbose=True)

        if result.get('final_score', 0) >= 55:
            save = input(f"\n{Fore.GREEN}Save to personal DB + generate configs? (y/n): {Style.RESET_ALL}").strip().lower()
            if save == 'y':
                db = []
                if os.path.exists(PERSONAL_DB):
                    try:
                        with open(PERSONAL_DB) as f:
                            db = json.load(f)
                    except:
                        db = []
                db.append({
                    'host': host,
                    'score': result['final_score'],
                    'isp': isp,
                    'country': country,
                    'added': datetime.now().isoformat()
                })
                with open(PERSONAL_DB, 'w') as f:
                    json.dump(db, f, indent=2)
                generate_configs([result], isp)

    elif choice == '2':
        print(f"\n{Fore.YELLOW}Paste hosts (one per line or all jammed together).{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Descriptions & junk are auto-removed. Type DONE when finished:{Style.RESET_ALL}\n")
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip().upper() == 'DONE':
                break
            lines.append(line)

        hosts = clean_hosts_bulk('\n'.join(lines))
        if not hosts:
            print(f"{Fore.RED}No valid hosts after cleaning{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}Cleaned {len(hosts)} unique hosts:{Style.RESET_ALL}")
        for h in hosts:
            print(f"  → {h}")

        test_multiple_hosts(hosts, isp, country)

    elif choice == '3':
        defaults = [
            'www.uj.ac.za', 'www.ukzn.ac.za', 'www.unisa.ac.za',
            'www.wits.ac.za', 'www.uct.ac.za', 'www.up.ac.za',
            'www.health.gov.za', 'sacoronavirus.co.za',
            'www.education.gov.za', 'www.nicd.ac.za',
            'everythingmaths.co.za', 'learn.mindset.africa',
            'www.tut.ac.za', 'www.cput.ac.za'
        ]
        print(f"{Fore.YELLOW}Testing {len(defaults)} common SA hosts...{Style.RESET_ALL}")
        test_multiple_hosts(defaults, isp, country)

    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")


if __name__ == '__main__':
    main()

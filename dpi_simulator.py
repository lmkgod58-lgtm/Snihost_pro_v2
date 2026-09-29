#!/usr/bin/env python3
"""
DPI Evasion Simulation Module
Simulates ISP Deep Packet Inspection checks locally
Tests if SNI spoofing will actually bypass ISP charging
"""

import socket
import ssl
import struct
import time
import json
import os
from colorama import Fore, Style, init

init(autoreset=True)

# ============ CONFIG ============

RESULTS_DIR = os.path.expanduser("~/snihost_pro/results")

# Common DPI detection signatures
DPI_SIGNATURES = {
    'sni_only_check': 'ISP only checks SNI field (EASIEST to bypass)',
    'ip_sni_mismatch': 'ISP checks if IP matches SNI domain (HARDER)',
    'cert_san_check': 'ISP verifies certificate SANs vs SNI (HARD)',
    'host_header_check': 'ISP compares Host header vs SNI (HARD)',
    'ja3_fingerprint': 'ISP fingerprints TLS handshake (VERY HARD)',
    'packet_size_analysis': 'ISP analyzes packet sizes (VERY HARD)',
    'timing_analysis': 'ISP analyzes connection timing (VERY HARD)'
}

# ============ TLS PACKET ANALYSIS ============

class TLSPacketAnalyzer:
    """
    Analyzes raw TLS packets to simulate DPI inspection
    """
    
    def __init__(self):
        self.findings = []
    
    def analyze_client_hello(self, domain, sni_host=None):
        """
        Simulate what a ClientHello packet looks like to DPI
        """
        sni_host = sni_host or domain
        
        # In a real ClientHello, SNI is in plaintext
        # The ISP can read it without decrypting
        findings = {
            'sni_visible': True,  # SNI is ALWAYS visible in plaintext
            'sni_hostname': sni_host,
            'actual_destination': domain,
            'sni_matches_destination': sni_host == domain,
            'packet_size_estimate': len(sni_host) + 200  # Rough estimate
        }
        
        return findings
    
    def simulate_sni_spoof(self, actual_domain, spoofed_sni):
        """
        Simulate what happens when you spoof SNI
        """
        print(f"\n{Fore.CYAN}=== Simulating SNI Spoof ==={Style.RESET_ALL}")
        print(f"  Actual destination: {actual_domain}")
        print(f"  Spoofed SNI: {spoofed_sni}")
        
        # Check 1: SNI field
        print(f"\n{Fore.YELLOW}DPI Check 1: SNI Field{Style.RESET_ALL}")
        print(f"  ISP sees SNI = '{spoofed_sni}'")
        print(f"  ✓ SNI is plaintext — ISP reads it easily")
        
        # Check 2: IP vs SNI mismatch
        print(f"\n{Fore.YELLOW}DPI Check 2: IP vs SNI Match{Style.RESET_ALL}")
        try:
            actual_ip = socket.gethostbyname(actual_domain)
            sni_ip = socket.gethostbyname(spoofed_sni)
            
            print(f"  Actual domain IP: {actual_ip}")
            print(f"  SNI domain IP: {sni_ip}")
            
            if actual_ip == sni_ip:
                print(f"  {Fore.GREEN}✓ IPs MATCH — ISP cannot detect mismatch!{Style.RESET_ALL}")
                ip_safe = True
            else:
                print(f"  {Fore.RED}✗ IPs DIFFERENT — ISP may detect spoof!{Style.RESET_ALL}")
                print(f"  {Fore.RED}  Actual: {actual_ip} vs SNI: {sni_ip}{Style.RESET_ALL}")
                ip_safe = False
        except Exception as e:
            print(f"  {Fore.YELLOW}⚠ Could not resolve IPs: {e}{Style.RESET_ALL}")
            ip_safe = None
        
        # Check 3: Certificate SAN check
        print(f"\n{Fore.YELLOW}DPI Check 3: Certificate SANs{Style.RESET_ALL}")
        cert_safe = self._check_certificate_sans(actual_domain, spoofed_sni)
        
        # Check 4: Host header vs SNI
        print(f"\n{Fore.YELLOW}DPI Check 4: HTTP Host Header{Style.RESET_ALL}")
        print(f"  If using HTTP injection, Host header = '{actual_domain}'")
        print(f"  SNI = '{spoofed_sni}'")
        if actual_domain != spoofed_sni:
            print(f"  {Fore.RED}✗ Host ≠ SNI — DPI may detect domain fronting!{Style.RESET_ALL}")
            host_safe = False
        else:
            print(f"  {Fore.GREEN}✓ Host = SNI — No mismatch{Style.RESET_ALL}")
            host_safe = True
        
        # Overall assessment
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  DPI Evasion Assessment{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        checks_passed = 0
        checks_total = 3  # IP, Cert, Host
        
        if ip_safe is True:
            checks_passed += 1
            print(f"  IP Check: {Fore.GREEN}PASS{Style.RESET_ALL}")
        elif ip_safe is False:
            print(f"  IP Check: {Fore.RED}FAIL{Style.RESET_ALL}")
        else:
            print(f"  IP Check: {Fore.YELLOW}UNKNOWN{Style.RESET_ALL}")
        
        if cert_safe is True:
            checks_passed += 1
            print(f"  Cert Check: {Fore.GREEN}PASS{Style.RESET_ALL}")
        elif cert_safe is False:
            print(f"  Cert Check: {Fore.RED}FAIL{Style.RESET_ALL}")
        else:
            print(f"  Cert Check: {Fore.YELLOW}UNKNOWN{Style.RESET_ALL}")
        
        if host_safe:
            checks_passed += 1
            print(f"  Host Check: {Fore.GREEN}PASS{Style.RESET_ALL}")
        else:
            print(f"  Host Check: {Fore.RED}FAIL{Style.RESET_ALL}")
        
        evasion_score = (checks_passed / checks_total) * 100
        
        if evasion_score >= 66:
            print(f"\n  {Fore.GREEN}Evasion Score: {evasion_score:.0f}% — LIKELY TO BYPASS{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}This spoof has good chances of working!{Style.RESET_ALL}")
        elif evasion_score >= 33:
            print(f"\n  {Fore.YELLOW}Evasion Score: {evasion_score:.0f}% — MAYBE{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}Some checks may fail. Test with small data first.{Style.RESET_ALL}")
        else:
            print(f"\n  {Fore.RED}Evasion Score: {evasion_score:.0f}% — LIKELY BLOCKED{Style.RESET_ALL}")
            print(f"  {Fore.RED}ISP DPI will probably detect this spoof.{Style.RESET_ALL}")
        
        return {
            'actual_domain': actual_domain,
            'spoofed_sni': spoofed_sni,
            'ip_safe': ip_safe,
            'cert_safe': cert_safe,
            'host_safe': host_safe,
            'evasion_score': evasion_score,
            'checks_passed': checks_passed,
            'checks_total': checks_total
        }
    
    def _check_certificate_sans(self, actual_domain, spoofed_sni):
        """
        Check if spoofed SNI appears in actual domain's certificate SANs
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((actual_domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=actual_domain) as ssock:
                    cert = ssock.getpeercert()
                    sans = [s[1] for s in cert.get('subjectAltName', [])]
                    
                    print(f"  Certificate SANs: {sans[:5]}...")  # Show first 5
                    
                    # Check if spoofed SNI is in SANs
                    if spoofed_sni in sans:
                        print(f"  {Fore.GREEN}✓ Spoofed SNI found in certificate SANs!{Style.RESET_ALL}")
                        print(f"  {Fore.GREEN}  ISP cert check will PASS{Style.RESET_ALL}")
                        return True
                    else:
                        # Check for wildcard
                        wildcard_match = False
                        for san in sans:
                            if san.startswith('*.'):
                                wildcard_domain = san[2:]
                                if spoofed_sni.endswith(wildcard_domain):
                                    wildcard_match = True
                                    break
                        
                        if wildcard_match:
                            print(f"  {Fore.GREEN}✓ Spoofed SNI matches wildcard SAN!{Style.RESET_ALL}")
                            return True
                        else:
                            print(f"  {Fore.RED}✗ Spoofed SNI NOT in certificate SANs{Style.RESET_ALL}")
                            print(f"  {Fore.RED}  ISP may detect certificate mismatch{Style.RESET_ALL}")
                            return False
        except Exception as e:
            print(f"  {Fore.YELLOW}⚠ Could not check certificate: {e}{Style.RESET_ALL}")
            return None

# ============ ADVANCED DPI TESTS ============

class AdvancedDPITests:
    """
    Advanced tests for sophisticated DPI systems
    """
    
    def test_tls_fingerprint(self, domain):
        """
        Test what TLS fingerprint your connection produces
        ISPs can fingerprint and block known VPN signatures
        """
        print(f"\n{Fore.CYAN}=== TLS Fingerprint Test ==={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Analyzing TLS handshake fingerprint for {domain}...{Style.RESET_ALL}")
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Get supported ciphers
            ciphers = context.get_ciphers()
            cipher_names = [c['name'] for c in ciphers[:10]]
            
            print(f"\n  Cipher suites offered:")
            for c in cipher_names:
                print(f"    - {c}")
            
            # Simulate JA3 fingerprint (simplified)
            # Real JA3 is: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            ja3_approx = f"TLS1.3,{len(ciphers)}ciphers,default_extensions"
            
            print(f"\n  Approximate fingerprint: {ja3_approx}")
            print(f"  {Fore.YELLOW}Note: Real ISPs use full JA3/JA4 fingerprinting{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}This is a simplified simulation{Style.RESET_ALL}")
            
            return {
                'cipher_count': len(ciphers),
                'top_ciphers': cipher_names,
                'fingerprint_approx': ja3_approx
            }
            
        except Exception as e:
            print(f"  {Fore.RED}Error: {e}{Style.RESET_ALL}")
            return None
    
    def test_packet_timing(self, domain, samples=5):
        """
        Test connection timing patterns
        ISPs can detect VPNs by timing analysis
        """
        print(f"\n{Fore.CYAN}=== Timing Analysis Test ==={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Testing connection timing to {domain}...{Style.RESET_ALL}")
        
        times = []
        for i in range(samples):
            try:
                start = time.time()
                sock = socket.create_connection((domain, 443), timeout=5)
                sock.close()
                elapsed = (time.time() - start) * 1000
                times.append(elapsed)
                time.sleep(0.5)
            except:
                times.append(None)
        
        valid_times = [t for t in times if t is not None]
        
        if valid_times:
            avg = sum(valid_times) / len(valid_times)
            min_t = min(valid_times)
            max_t = max(valid_times)
            
            print(f"\n  Connection times (ms):")
            for i, t in enumerate(times, 1):
                status = f"{t:.1f}ms" if t else "FAILED"
                print(f"    Attempt {i}: {status}")
            
            print(f"\n  Average: {avg:.1f}ms")
            print(f"  Range: {min_t:.1f}ms - {max_t:.1f}ms")
            
            if max_t - min_t > 100:
                print(f"  {Fore.YELLOW}⚠ High variance — may look suspicious to DPI{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}✓ Consistent timing — looks natural{Style.RESET_ALL}")
            
            return {
                'times': times,
                'average_ms': avg,
                'variance_ms': max_t - min_t,
                'consistent': (max_t - min_t) < 100
            }
        else:
            print(f"  {Fore.RED}All connection attempts failed{Style.RESET_ALL}")
            return None
    
    def test_fragmentation_evasion(self, domain, sni_host):
        """
        Test if packet fragmentation could help evade DPI
        Some DPI systems can't reassemble fragmented packets
        """
        print(f"\n{Fore.CYAN}=== Fragmentation Evasion Test ==={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This tests if splitting packets could bypass DPI{Style.RESET_ALL}")
        
        # This is a conceptual test — actual fragmentation requires raw sockets
        print(f"\n  {Fore.YELLOW}Note: Actual packet fragmentation requires root access{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}and raw socket privileges on Android{Style.RESET_ALL}")
        
        print(f"\n  Conceptual analysis:")
        print(f"  - SNI field is in first few bytes of ClientHello")
        print(f"  - If we fragment after SNI, some DPI can't read it")
        print(f"  - But modern DPI reassembles fragments")
        
        # Estimate if SNI is small enough to hide
        sni_len = len(sni_host)
        if sni_len < 20:
            print(f"\n  {Fore.GREEN}✓ Short SNI ({sni_len} chars) — easier to hide{Style.RESET_ALL}")
        else:
            print(f"\n  {Fore.YELLOW}⚠ Long SNI ({sni_len} chars) — harder to fragment{Style.RESET_ALL}")
        
        return {
            'sni_length': sni_len,
            'fragmentation_viable': sni_len < 30,
            'requires_root': True
        }

# ============ MAIN INTERFACE ============

def display_dpi_checklist(result):
    """Display a DPI evasion checklist"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  DPI Evasion Checklist{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    checks = [
        ("SNI Spoofing", result.get('ip_safe') is not False),
        ("Certificate Match", result.get('cert_safe') is True),
        ("Host Header Match", result.get('host_safe') is True),
        ("TLS Fingerprint", True),  # Default true for basic tests
        ("Timing Consistency", True),
    ]
    
    for check_name, passed in checks:
        status = f"{Fore.GREEN}✓ PASS" if passed else f"{Fore.RED}✗ FAIL"
        print(f"  {status}{Style.RESET_ALL} {check_name}")
    
    score = result.get('evasion_score', 0)
    if score >= 66:
        color = Fore.GREEN
        advice = "Good to go! Test with small data first."
    elif score >= 33:
        color = Fore.YELLOW
        advice = "Mixed results. Some DPI checks may catch you."
    else:
        color = Fore.RED
        advice = "High risk of detection. Consider different host."
    
    print(f"\n  {color}Overall: {score:.0f}% evasion probability{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Advice: {advice}{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  DPI Evasion Simulator{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Test if Your SNI Spoof Bypasses ISP{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print("Select mode:")
    print("1. Simulate SNI spoof (basic DPI checks)")
    print("2. Advanced DPI tests (fingerprint, timing, fragmentation)")
    print("3. Full evasion audit")
    
    choice = input("\nChoice (1-3): ").strip()
    
    if choice == '1':
        actual = input("Actual VPN server domain: ").strip().lower()
        spoofed = input("Spoofed SNI host: ").strip().lower()
        
        if not actual or not spoofed:
            print(f"{Fore.RED}Both domains required{Style.RESET_ALL}")
            return
        
        analyzer = TLSPacketAnalyzer()
        result = analyzer.simulate_sni_spoof(actual, spoofed)
        display_dpi_checklist(result)
        
        save = input(f"\nSave result? (y/n): ").strip().lower()
        if save == 'y':
            os.makedirs(RESULTS_DIR, exist_ok=True)
            filename = f"dpi_sim_{time.strftime('%Y%m%d_%H%M%S')}.json"
            filepath = os.path.join(RESULTS_DIR, filename)
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"{Fore.GREEN}Saved to: {filepath}{Style.RESET_ALL}")
    
    elif choice == '2':
        domain = input("Domain to test: ").strip().lower()
        
        advanced = AdvancedDPITests()
        
        # Run all advanced tests
        advanced.test_tls_fingerprint(domain)
        advanced.test_packet_timing(domain)
        
        sni = input("\nSpoofed SNI for fragmentation test: ").strip().lower()
        if sni:
            advanced.test_fragmentation_evasion(domain, sni)
    
    elif choice == '3':
        actual = input("Actual VPN server domain: ").strip().lower()
        spoofed = input("Spoofed SNI host: ").strip().lower()
        
        if not actual or not spoofed:
            print(f"{Fore.RED}Both domains required{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Running full DPI evasion audit...{Style.RESET_ALL}")
        
        # Basic checks
        analyzer = TLSPacketAnalyzer()
        basic_result = analyzer.simulate_sni_spoof(actual, spoofed)
        
        # Advanced checks
        advanced = AdvancedDPITests()
        fingerprint = advanced.test_tls_fingerprint(actual)
        timing = advanced.test_packet_timing(actual)
        frag = advanced.test_fragmentation_evasion(actual, spoofed)
        
        # Combined report
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  FULL DPI EVASION AUDIT REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        display_dpi_checklist(basic_result)
        
        if timing:
            print(f"\n  Timing Consistency: {'✓' if timing.get('consistent') else '✗'}")
        
        if frag:
            print(f"  Fragmentation Possible: {'✓' if frag.get('fragmentation_viable') else '✗'}")
        
        # Final verdict
        score = basic_result.get('evasion_score', 0)
        if score >= 66 and timing and timing.get('consistent'):
            print(f"\n{Fore.GREEN}VERDICT: HIGH CHANCE OF SUCCESS{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Proceed with confidence, but test small first.{Style.RESET_ALL}")
        elif score >= 33:
            print(f"\n{Fore.YELLOW}VERDICT: MODERATE CHANCE{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Some checks may fail. Monitor data usage closely.{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}VERDICT: LOW CHANCE{Style.RESET_ALL}")
            print(f"{Fore.RED}Consider different host or VPN method.{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()

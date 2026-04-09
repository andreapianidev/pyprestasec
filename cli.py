#!/usr/bin/env python3
"""
PyPrestaSec CLI - Terminal interface (no web server)
Usage: python cli.py <url> [--api-key KEY]
"""

import sys
import argparse
from src.scanner import PrestaShopScanner
from src.config import NVD_API_KEY, SEVERITY_ICONS


def print_banner():
    print("""
╔════════════════════════════════════════════════════════════╗
║           🛡️  PyPrestaSec - PrestaShop Scanner             ║
║              Terminal Edition (No Web Server)              ║
╚════════════════════════════════════════════════════════════╝
""")


def print_result(result):
    print(f"\n{'='*60}")
    print(f"📍 Target: {result.url}")
    
    if result.detected_version:
        v = result.detected_version
        print(f"📦 Version: {v.version} (detected from {v.source}, {v.confidence} confidence)")
    else:
        print("📦 Version: Not detected")
    
    print(f"🕐 Scan time: {result.scan_date.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    
    # Summary
    print("\n📊 VULNERABILITY SUMMARY:")
    print(f"   {SEVERITY_ICONS['CRITICAL']} CRITICAL: {result.critical_count}")
    print(f"   {SEVERITY_ICONS['HIGH']} HIGH:     {result.high_count}")
    print(f"   {SEVERITY_ICONS['MEDIUM']} MEDIUM:   {result.medium_count}")
    print(f"   {SEVERITY_ICONS['LOW']} LOW:      {result.low_count}")
    print(f"   ─────────────────────────")
    print(f"   📋 TOTAL:   {result.total_cves}")
    
    # Details
    if result.vulnerabilities:
        print(f"\n📋 VULNERABILITY DETAILS:")
        print("-" * 80)
        
        for vuln in result.vulnerabilities:
            icon = SEVERITY_ICONS.get(vuln.severity, '⚪')
            print(f"\n{icon} {vuln.cve_id}")
            print(f"   Severity: {vuln.severity} | CVSS: {vuln.cvss_score or 'N/A'}")
            print(f"   Published: {vuln.published_date[:10] if vuln.published_date else 'N/A'}")
            print(f"   Description: {vuln.description[:100]}...")
            if vuln.references:
                print(f"   Reference: {vuln.references[0][:70]}...")
        print("-" * 80)
    else:
        print("\n✅ No vulnerabilities found!")
    
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Scan PrestaShop websites for vulnerabilities'
    )
    parser.add_argument('url', help='PrestaShop URL to scan')
    parser.add_argument(
        '--api-key', 
        help='NVD API key (optional)',
        default=NVD_API_KEY
    )
    parser.add_argument(
        '--max-cves', 
        type=int, 
        default=100,
        help='Maximum CVEs to fetch (default: 100)'
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    print(f"[+] Starting scan of {args.url}...")
    print(f"[*] Using API key: {'Yes' if args.api_key else 'No (slower)'}")
    print()
    
    try:
        scanner = PrestaShopScanner(api_key=args.api_key)
        result = scanner.scan(args.url, check_all_cves=True)
        print_result(result)
        
        # Save to file
        import json
        from datetime import datetime
        
        filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump({
                'url': result.url,
                'version': result.detected_version.version if result.detected_version else None,
                'scan_date': result.scan_date.isoformat(),
                'total_cves': result.total_cves,
                'vulnerabilities': [
                    {
                        'cve_id': v.cve_id,
                        'severity': v.severity,
                        'cvss_score': v.cvss_score,
                        'description': v.description,
                        'published': v.published_date
                    }
                    for v in result.vulnerabilities
                ]
            }, f, indent=2)
        
        print(f"💾 Results saved to: {filename}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

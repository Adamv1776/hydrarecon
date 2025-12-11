#!/usr/bin/env python3
"""
Test OSINT Data Collection - Demonstrates bypass techniques
"""

import asyncio
import sys
sys.path.insert(0, '.')

from core.advanced_http import AdvancedHTTPClient, OSINTDataCollector


async def test_osint_collection():
    """Test various OSINT data collection techniques."""
    print("=" * 70)
    print("  OSINT Data Collection Test - Bypass Techniques Demo")
    print("=" * 70)
    print()
    
    # Test target
    test_domain = "github.com"
    
    # Create collector
    collector = OSINTDataCollector()
    
    try:
        # Test 1: Subdomain Enumeration (multiple free sources)
        print("[1] SUBDOMAIN ENUMERATION (No API keys needed)")
        print("-" * 50)
        subdomains = await collector.enumerate_subdomains(test_domain)
        print(f"    ✓ Found {len(subdomains)} subdomains for {test_domain}")
        if subdomains[:5]:
            for sub in subdomains[:5]:
                print(f"      - {sub}")
            if len(subdomains) > 5:
                print(f"      ... and {len(subdomains) - 5} more")
        print()
        
        # Test 2: Technology Detection
        print("[2] TECHNOLOGY DETECTION (Direct scraping)")
        print("-" * 50)
        tech = await collector.detect_technologies(f"https://{test_domain}")
        for category, items in tech.items():
            if items:
                print(f"    {category}: {', '.join(items)}")
        print()
        
        # Test 3: WHOIS Lookup
        print("[3] WHOIS LOOKUP (Web sources)")
        print("-" * 50)
        whois_data = await collector.whois_lookup(test_domain)
        for key, value in whois_data.items():
            if value and key != "source":
                print(f"    {key}: {value}")
        print()
        
        # Test 4: Advanced HTTP Client Features
        print("[4] ADVANCED HTTP CLIENT DEMO")
        print("-" * 50)
        client = collector.client
        
        # Show rotating User-Agents
        print("    Rotating User-Agents:")
        for i in range(3):
            ua = client._get_random_ua()
            print(f"      Request {i+1}: {ua[:60]}...")
        print()
        
        # Test request with browser headers
        result = await client.get(
            "https://httpbin.org/headers",
            as_browser=True
        )
        if result.success:
            headers_sent = result.data.get("headers", {})
            print("    Browser-like Headers Sent:")
            for key in ["User-Agent", "Accept", "Accept-Language", "Sec-Fetch-Mode"]:
                if key in headers_sent:
                    val = headers_sent[key]
                    if len(val) > 50:
                        val = val[:50] + "..."
                    print(f"      {key}: {val}")
        print()
        
        # Test 5: IP Info (real data)
        print("[5] IP INFORMATION (Real API data)")
        print("-" * 50)
        ip_result = await client.get("https://ipinfo.io/8.8.8.8/json", as_browser=False)
        if ip_result.success:
            ip_data = ip_result.data
            print(f"    IP: {ip_data.get('ip')}")
            print(f"    Org: {ip_data.get('org')}")
            print(f"    Location: {ip_data.get('city')}, {ip_data.get('country')}")
        print()
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await collector.close()
    
    print("=" * 70)
    print("  Summary: Python bypasses CORS entirely (it's browser-only)")
    print("  The advanced HTTP client provides:")
    print("    - Rotating User-Agents (evade bot detection)")
    print("    - Browser fingerprint spoofing")
    print("    - Optional Tor/proxy support")
    print("    - Automatic retry with backoff")
    print("    - Rate limit handling")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_osint_collection())

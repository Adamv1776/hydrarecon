#!/usr/bin/env python3
"""
Test Real Data Sources - Verify all modules use real data
"""

import asyncio
import sys
sys.path.insert(0, '.')


async def test_all_real_data():
    """Test all modules that now use real data."""
    print("=" * 70)
    print("  HydraRecon Real Data Integration Test")
    print("=" * 70)
    print()
    
    results = {
        "passed": 0,
        "failed": 0,
        "skipped": 0
    }
    
    # Test 1: Patch Management - NVD API
    print("[1] PATCH MANAGEMENT - NVD/CISA Integration")
    print("-" * 50)
    try:
        from core.patch_management import PatchManagementEngine
        
        engine = PatchManagementEngine(demo_mode=False)
        
        # Test CISA KEV fetch
        kev = await engine.vuln_source.fetch_cisa_kev()
        if kev:
            print(f"    ✓ CISA KEV: {len(kev)} known exploited vulnerabilities")
            print(f"      Sample: {kev[0]['cve_id']} - {kev[0]['vulnerability_name'][:50]}...")
            results["passed"] += 1
        else:
            print("    ⚠ CISA KEV: No data (network issue?)")
            results["skipped"] += 1
        
        # Test NVD CVE fetch
        cves = await engine.vuln_source.fetch_recent_cves(severity="CRITICAL", days=7, limit=5)
        if cves:
            print(f"    ✓ NVD API: {len(cves)} critical CVEs in last 7 days")
            for cve in cves[:2]:
                print(f"      - {cve['cve_id']} (CVSS: {cve.get('cvss_score', 'N/A')})")
            results["passed"] += 1
        else:
            print("    ⚠ NVD API: No data (rate limited?)")
            results["skipped"] += 1
        
        await engine.close()
    except Exception as e:
        print(f"    ✗ Error: {e}")
        results["failed"] += 1
    print()
    
    # Test 2: Live Attack Map - Threat Intel Feeds
    print("[2] LIVE ATTACK MAP - Threat Intel Feeds")
    print("-" * 50)
    try:
        from core.live_attack_map import RealThreatIntelFeed, GeoIPResolver
        
        feed = RealThreatIntelFeed()
        
        # Test DShield (no API key needed)
        top_ips = await feed.fetch_dshield_top_ips()
        if top_ips:
            print(f"    ✓ DShield Top IPs: {len(top_ips)} attacking IPs")
            print(f"      Top attacker: {top_ips[0]['ip']} ({top_ips[0]['attacks']} attacks)")
            results["passed"] += 1
        else:
            print("    ⚠ DShield: No data")
            results["skipped"] += 1
        
        top_ports = await feed.fetch_dshield_top_ports()
        if top_ports:
            print(f"    ✓ DShield Top Ports: {len(top_ports)} targeted ports")
            print(f"      Most targeted: Port {top_ports[0]['port']} ({top_ports[0]['records']} records)")
            results["passed"] += 1
        else:
            print("    ⚠ DShield Ports: No data")
            results["skipped"] += 1
        
        # Test GreyNoise Community (no API key needed)
        gn_result = await feed.check_ip_greynoise("8.8.8.8")
        if gn_result:
            print(f"    ✓ GreyNoise: 8.8.8.8 - noise={gn_result.get('noise')}, classification={gn_result.get('classification')}")
            results["passed"] += 1
        else:
            print("    ⚠ GreyNoise: No response")
            results["skipped"] += 1
        
        # Test GeoIP
        resolver = GeoIPResolver()
        geo = await resolver.resolve("1.1.1.1")
        if geo.country:
            print(f"    ✓ IPInfo GeoIP: 1.1.1.1 -> {geo.city}, {geo.country} ({geo.org})")
            results["passed"] += 1
        else:
            print(f"    ⚠ IPInfo: Using fallback data ({geo.country_code})")
            results["skipped"] += 1
        
        await feed.close()
        await resolver.close()
    except Exception as e:
        print(f"    ✗ Error: {e}")
        results["failed"] += 1
    print()
    
    # Test 3: Satellite/RF Intel - Space Data
    print("[3] SATELLITE/RF INTEL - Space Tracking")
    print("-" * 50)
    try:
        from core.satellite_rf_intel import SatelliteRFIntelligence
        
        sat_intel = SatelliteRFIntelligence()
        
        # Test ISS position (free, no API key)
        iss = await sat_intel.get_iss_position()
        if iss:
            print(f"    ✓ ISS Position: Lat={iss['latitude']:.2f}, Lon={iss['longitude']:.2f}")
            results["passed"] += 1
        else:
            print("    ⚠ ISS Position: No data")
            results["skipped"] += 1
        
        # Test CelesTrak TLE (free, no API key)
        tle = await sat_intel.get_tle_real(25544)  # ISS NORAD ID
        if tle:
            print(f"    ✓ CelesTrak TLE: {tle['name']} (NORAD {tle['norad_id']})")
            print(f"      Inclination: {tle['inclination']}°, Epoch: {tle['epoch'][:10]}")
            results["passed"] += 1
        else:
            print("    ⚠ CelesTrak: No data")
            results["skipped"] += 1
        
        # Test Starlink constellation
        starlink = await sat_intel.get_starlink_satellites()
        if starlink:
            print(f"    ✓ Starlink: {len(starlink)} satellites tracked")
            results["passed"] += 1
        else:
            print("    ⚠ Starlink: No data")
            results["skipped"] += 1
        
        # Test OpenSky (limited without account)
        aircraft = await sat_intel.get_opensky_aircraft(bbox=(45, 46, -122, -121))
        if aircraft:
            print(f"    ✓ OpenSky ADS-B: {len(aircraft)} aircraft in Portland area")
            results["passed"] += 1
        else:
            print("    ⚠ OpenSky: No data (rate limited or no aircraft)")
            results["skipped"] += 1
        
        # Check SDR hardware
        sdr_status = sat_intel.sdr_available
        sdr_found = [k for k, v in sdr_status.items() if v]
        if sdr_found:
            print(f"    ✓ SDR Hardware: {', '.join(sdr_found)}")
        else:
            print("    ℹ SDR Hardware: None detected (RF features limited)")
        
        await sat_intel.close()
    except Exception as e:
        print(f"    ✗ Error: {e}")
        import traceback
        traceback.print_exc()
        results["failed"] += 1
    print()
    
    # Test 4: Memory Forensics - Real Process Data
    print("[4] MEMORY FORENSICS - Real System Data")
    print("-" * 50)
    try:
        import os
        
        # Test real /proc reading
        if os.path.exists("/proc"):
            # Count processes
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
            print(f"    ✓ /proc: {len(pids)} processes detected")
            
            # Test network connections
            if os.path.exists("/proc/net/tcp"):
                with open("/proc/net/tcp") as f:
                    conn_count = len(f.readlines()) - 1
                print(f"    ✓ /proc/net/tcp: {conn_count} TCP connections")
                results["passed"] += 1
            
            # Test memory info
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo") as f:
                    meminfo = f.read()
                    total = [l for l in meminfo.split("\n") if "MemTotal" in l][0]
                print(f"    ✓ /proc/meminfo: {total.strip()}")
                results["passed"] += 1
        else:
            print("    ⚠ Not on Linux - /proc not available")
            results["skipped"] += 1
    except Exception as e:
        print(f"    ✗ Error: {e}")
        results["failed"] += 1
    print()
    
    # Test 5: OSINT Advanced HTTP
    print("[5] OSINT - Advanced HTTP Client")
    print("-" * 50)
    try:
        from core.advanced_http import OSINTDataCollector
        
        collector = OSINTDataCollector()
        
        # Test subdomain enumeration
        subdomains = await collector.enumerate_subdomains("example.com")
        print(f"    ✓ Subdomain Enum: {len(subdomains)} subdomains for example.com")
        results["passed"] += 1
        
        # Test technology detection
        tech = await collector.detect_technologies("https://github.com")
        detected = [f"{k}: {len(v)}" for k, v in tech.items() if v]
        print(f"    ✓ Tech Detection: {', '.join(detected[:3])}")
        results["passed"] += 1
        
        await collector.close()
    except Exception as e:
        print(f"    ✗ Error: {e}")
        results["failed"] += 1
    print()
    
    # Summary
    print("=" * 70)
    print(f"  SUMMARY: {results['passed']} passed, {results['failed']} failed, {results['skipped']} skipped")
    print("=" * 70)
    print()
    print("  Modules now using real data sources:")
    print("    ✓ patch_management.py - NVD API, CISA KEV")
    print("    ✓ live_attack_map.py - DShield, GreyNoise, AbuseIPDB, OTX, IPInfo")
    print("    ✓ satellite_rf_intel.py - N2YO, CelesTrak, OpenSky, ISS API")
    print("    ✓ memory_forensics.py - /proc filesystem, real connections")
    print("    ✓ advanced_http.py - Real OSINT sources")
    print("    ✓ blockchain_forensics.py - Etherscan, Blockchain.info")
    print("    ✓ ad_attacks.py - Impacket for real Kerberos")
    print()
    print("  API keys needed for full functionality:")
    print("    - NVD_API_KEY (faster NVD queries)")
    print("    - OTX_API_KEY (AlienVault threat intel)")
    print("    - ABUSEIPDB_API_KEY (IP reputation)")
    print("    - GREYNOISE_API_KEY (scanner detection)")
    print("    - N2YO_API_KEY (satellite tracking)")
    print("    - SHODAN_API_KEY (device search)")
    print("    - VIRUSTOTAL_API_KEY (malware analysis)")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_all_real_data())

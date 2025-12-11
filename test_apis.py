#!/usr/bin/env python3
"""
API Configuration Tester
Tests all configured APIs and reports their status.
"""

import asyncio
import sys
sys.path.insert(0, '.')

from core.config import Config
from core.data_sources import (
    DataSourceManager, DataSourceType,
    ShodanSource, VirusTotalSource, CensysSource,
    AbuseIPDBSource, AlienVaultOTXSource, SecurityTrailsSource,
    IPInfoSource, GreyNoiseSource, NVDSource, CrtShSource,
    EtherscanSource, BlockchainInfoSource, APICredential
)


async def test_api(name: str, source, test_target: str) -> dict:
    """Test a single API."""
    print(f"  Testing {name}...", end=" ", flush=True)
    try:
        result = await source.query(test_target)
        if result.success:
            print(f"✅ OK")
            return {"name": name, "status": "ok", "data_sample": bool(result.data)}
        else:
            print(f"❌ Failed: {result.error}")
            return {"name": name, "status": "failed", "error": result.error}
    except Exception as e:
        print(f"❌ Error: {e}")
        return {"name": name, "status": "error", "error": str(e)}
    finally:
        await source.close()


async def main():
    print("=" * 60)
    print("HydraRecon API Configuration Tester")
    print("=" * 60)
    
    config = Config()
    osint = config.osint
    
    # Test IPs and domains
    test_ip = "8.8.8.8"
    test_domain = "google.com"
    test_btc = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    
    results = []
    
    print("\n📡 Testing FREE APIs (no key required)...")
    print("-" * 40)
    
    # Free APIs
    free_sources = [
        ("AlienVault OTX", AlienVaultOTXSource(), test_ip),
        ("NVD (NIST)", NVDSource(), "CVE-2021-44228"),
        ("crt.sh", CrtShSource(), test_domain),
        ("IPInfo (limited)", IPInfoSource(), test_ip),
        ("GreyNoise Community", GreyNoiseSource(), test_ip),
        ("Blockchain.info", BlockchainInfoSource(), test_btc),
    ]
    
    for name, source, target in free_sources:
        result = await test_api(name, source, target)
        results.append(result)
    
    print("\n🔑 Testing APIs with configured keys...")
    print("-" * 40)
    
    # APIs requiring keys
    if osint.shodan_api_key:
        source = ShodanSource(APICredential(name="shodan", api_key=osint.shodan_api_key))
        results.append(await test_api("Shodan", source, test_ip))
    else:
        print("  Shodan: ⚠️  No API key configured")
        results.append({"name": "Shodan", "status": "no_key"})
    
    if osint.virustotal_api_key:
        source = VirusTotalSource(APICredential(name="virustotal", api_key=osint.virustotal_api_key))
        results.append(await test_api("VirusTotal", source, test_ip))
    else:
        print("  VirusTotal: ⚠️  No API key configured")
        results.append({"name": "VirusTotal", "status": "no_key"})
    
    if osint.censys_api_id and osint.censys_api_secret:
        source = CensysSource(APICredential(
            name="censys", 
            api_key=osint.censys_api_id,
            api_secret=osint.censys_api_secret
        ))
        results.append(await test_api("Censys", source, test_ip))
    else:
        print("  Censys: ⚠️  No API credentials configured")
        results.append({"name": "Censys", "status": "no_key"})
    
    if osint.securitytrails_api_key:
        source = SecurityTrailsSource(APICredential(name="securitytrails", api_key=osint.securitytrails_api_key))
        results.append(await test_api("SecurityTrails", source, test_domain))
    else:
        print("  SecurityTrails: ⚠️  No API key configured")
        results.append({"name": "SecurityTrails", "status": "no_key"})
    
    if hasattr(osint, 'abuseipdb_api_key') and osint.abuseipdb_api_key:
        source = AbuseIPDBSource(APICredential(name="abuseipdb", api_key=osint.abuseipdb_api_key))
        results.append(await test_api("AbuseIPDB", source, test_ip))
    else:
        print("  AbuseIPDB: ⚠️  No API key configured")
        results.append({"name": "AbuseIPDB", "status": "no_key"})
    
    if hasattr(osint, 'etherscan_api_key') and osint.etherscan_api_key:
        source = EtherscanSource(APICredential(name="etherscan", api_key=osint.etherscan_api_key))
        results.append(await test_api("Etherscan", source, "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"))
    else:
        print("  Etherscan: ⚠️  No API key configured")
        results.append({"name": "Etherscan", "status": "no_key"})
    
    if hasattr(osint, 'ipinfo_api_key') and osint.ipinfo_api_key:
        source = IPInfoSource(APICredential(name="ipinfo", api_key=osint.ipinfo_api_key))
        results.append(await test_api("IPInfo (with key)", source, test_ip))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    ok_count = sum(1 for r in results if r["status"] == "ok")
    failed_count = sum(1 for r in results if r["status"] in ("failed", "error"))
    no_key_count = sum(1 for r in results if r["status"] == "no_key")
    
    print(f"\n✅ Working: {ok_count}")
    print(f"❌ Failed: {failed_count}")
    print(f"⚠️  No key configured: {no_key_count}")
    
    if no_key_count > 0:
        print("\n💡 To configure API keys, see: docs/API_SETUP.md")
        print("   Or add them to ~/.hydrarecon/config.yaml")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(main())

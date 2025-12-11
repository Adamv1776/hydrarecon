#!/usr/bin/env python3
"""Quick API test."""
import asyncio
import sys
sys.path.insert(0, '/home/adam/hydra 1/hydrarecon')

from core.data_sources import CrtShSource, IPInfoSource, NVDSource, AlienVaultOTXSource

async def main():
    print("Testing free data sources...")
    
    # crt.sh
    print("  crt.sh...", end=" ", flush=True)
    s = CrtShSource()
    r = await s.query("example.com")
    print("OK" if r.success else "FAIL")
    await s.close()
    
    # IPInfo
    print("  IPInfo...", end=" ", flush=True)
    s = IPInfoSource()
    r = await s.query("8.8.8.8")
    if r.success:
        print(f"OK - {r.data.get('org', 'Unknown')}")
    else:
        print("FAIL")
    await s.close()
    
    # OTX
    print("  OTX...", end=" ", flush=True)
    s = AlienVaultOTXSource()
    r = await s.query("8.8.8.8", type="IPv4")
    print("OK" if r.success else "FAIL")
    await s.close()
    
    # NVD
    print("  NVD...", end=" ", flush=True)
    s = NVDSource()
    r = await s.query("CVE-2021-44228")
    if r.success:
        vulns = r.data.get("vulnerabilities", [])
        print(f"OK - {len(vulns)} results")
    else:
        print("FAIL")
    await s.close()
    
    print("\nDone!")

if __name__ == "__main__":
    asyncio.run(main())

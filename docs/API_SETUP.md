# HydraRecon API Setup Guide

This guide covers setting up API keys for real-time data integration across all modules.

## 🆓 Free Tier APIs (No Credit Card Required)

### 1. **Shodan** - Internet Device Search
- **URL**: https://account.shodan.io/register
- **Free Tier**: 100 queries/month, limited scanning
- **Upgrade**: $59/month for unlimited
- **Config Key**: `shodan_api_key`
- **Used By**: Network Mapper, Attack Surface, OSINT

### 2. **VirusTotal** - Malware & URL Scanning
- **URL**: https://www.virustotal.com/gui/join-us
- **Free Tier**: 500 lookups/day, 4 requests/min
- **Upgrade**: Contact for pricing
- **Config Key**: `virustotal_api_key`
- **Used By**: Malware Analysis, Threat Intel, OSINT

### 3. **AbuseIPDB** - IP Reputation
- **URL**: https://www.abuseipdb.com/register
- **Free Tier**: 1,000 checks/day
- **Upgrade**: $19/month for 50,000/day
- **Config Key**: `abuseipdb_api_key`
- **Used By**: Threat Intel, IP Reputation, Blue Team

### 4. **AlienVault OTX** - Threat Intelligence
- **URL**: https://otx.alienvault.com/
- **Free Tier**: Unlimited (community platform)
- **Config Key**: `alienvault_otx_key`
- **Used By**: Threat Intel, IOC Detection, OSINT

### 5. **Censys** - Internet Scanning
- **URL**: https://censys.io/register
- **Free Tier**: 250 queries/month
- **Upgrade**: $25/month for 10,000
- **Config Keys**: `censys_api_id`, `censys_api_secret`
- **Used By**: Network Mapper, Attack Surface, SSL Analysis

### 6. **SecurityTrails** - DNS Intelligence
- **URL**: https://securitytrails.com/app/signup
- **Free Tier**: 50 queries/month
- **Upgrade**: $50/month for 1,000
- **Config Key**: `securitytrails_api_key`
- **Used By**: DNS Recon, Subdomain Discovery, History

### 7. **Hunter.io** - Email Intelligence
- **URL**: https://hunter.io/users/sign_up
- **Free Tier**: 25 searches/month
- **Upgrade**: $49/month for 500
- **Config Key**: `hunter_api_key`
- **Used By**: Email Harvesting, OSINT

### 8. **IPInfo** - IP Geolocation
- **URL**: https://ipinfo.io/signup
- **Free Tier**: 50,000 requests/month
- **Config Key**: `ipinfo_api_key`
- **Used By**: Geolocation, ASN Lookup, IP Enrichment

### 9. **GreyNoise** - Scanner Detection
- **URL**: https://viz.greynoise.io/signup
- **Free Tier**: Community API (limited)
- **Upgrade**: Contact for pricing
- **Config Key**: `greynoise_api_key`
- **Used By**: Scanner Detection, Threat Intel

### 10. **URLScan.io** - URL Analysis
- **URL**: https://urlscan.io/user/signup
- **Free Tier**: Unlimited public scans
- **Config Key**: `urlscan_api_key`
- **Used By**: URL Analysis, Phishing Detection

### 11. **NVD (NIST)** - Vulnerability Database
- **URL**: https://nvd.nist.gov/developers/request-an-api-key
- **Free Tier**: 5 requests/30sec (with key), 10 requests/60sec (without)
- **Config Key**: `nvd_api_key`
- **Used By**: Vulnerability Scanning, CVE Lookup

### 12. **Vulners** - Vulnerability Intelligence
- **URL**: https://vulners.com/userinfo
- **Free Tier**: Limited searches
- **Upgrade**: Contact for pricing
- **Config Key**: `vulners_api_key`
- **Used By**: Exploit Search, Vulnerability Intel

### 13. **crt.sh** - Certificate Transparency (NO KEY REQUIRED)
- **URL**: https://crt.sh/
- **Free Tier**: Unlimited
- **Used By**: Subdomain Discovery, SSL Analysis

### 14. **Etherscan** - Ethereum Blockchain
- **URL**: https://etherscan.io/register
- **Free Tier**: 5 calls/second
- **Upgrade**: $199/month for higher limits
- **Config Key**: `etherscan_api_key`
- **Used By**: Blockchain Forensics, Crypto Analysis

### 15. **Have I Been Pwned** - Breach Data
- **URL**: https://haveibeenpwned.com/API/Key
- **Free Tier**: None (paid API)
- **Pricing**: $3.50/month
- **Config Key**: `haveibeenpwned_api_key`
- **Used By**: Credential Checking, Breach Analysis

---

## 🔧 Configuration

### Option 1: Config File (~/.hydrarecon/config.yaml)

```yaml
osint:
  shodan_api_key: "YOUR_SHODAN_KEY"
  virustotal_api_key: "YOUR_VT_KEY"
  abuseipdb_api_key: "YOUR_ABUSEIPDB_KEY"
  censys_api_id: "YOUR_CENSYS_ID"
  censys_api_secret: "YOUR_CENSYS_SECRET"
  securitytrails_api_key: "YOUR_ST_KEY"
  hunter_api_key: "YOUR_HUNTER_KEY"
  ipinfo_api_key: "YOUR_IPINFO_KEY"
  alienvault_otx_key: "YOUR_OTX_KEY"
  etherscan_api_key: "YOUR_ETHERSCAN_KEY"
  nvd_api_key: "YOUR_NVD_KEY"
```

### Option 2: Environment Variables

```bash
export SHODAN_API_KEY="YOUR_SHODAN_KEY"
export VIRUSTOTAL_API_KEY="YOUR_VT_KEY"
export ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_KEY"
export CENSYS_API_ID="YOUR_CENSYS_ID"
export CENSYS_API_SECRET="YOUR_CENSYS_SECRET"
export SECURITYTRAILS_API_KEY="YOUR_ST_KEY"
export HUNTER_API_KEY="YOUR_HUNTER_KEY"
export IPINFO_API_KEY="YOUR_IPINFO_KEY"
export ALIENVAULT_OTX_KEY="YOUR_OTX_KEY"
export ETHERSCAN_API_KEY="YOUR_ETHERSCAN_KEY"
export NVD_API_KEY="YOUR_NVD_KEY"
```

### Option 3: In-App Settings

Navigate to **Settings → API Keys** in the application to configure keys through the GUI.

---

## 📊 Data Source Coverage by Module

| Module | Free Sources | Paid Sources |
|--------|-------------|--------------|
| OSINT | OTX, crt.sh, IPInfo | Shodan, Censys, SecurityTrails |
| Threat Intel | OTX, GreyNoise | VirusTotal, AbuseIPDB |
| Network Mapper | crt.sh | Shodan, Censys |
| Vulnerability | NVD, ExploitDB | Vulners |
| Malware Analysis | OTX | VirusTotal |
| Blockchain | Blockchain.info | Etherscan, Chainalysis |
| Email Security | - | Hunter, HIBP |
| DNS Recon | crt.sh | SecurityTrails, PassiveTotal |

---

## 🚀 Quick Start - Essential Free APIs

For basic functionality, register for these 5 free APIs:

1. **Shodan** - Network intelligence
2. **VirusTotal** - Malware scanning
3. **AlienVault OTX** - Threat feeds
4. **Censys** - Internet scanning
5. **IPInfo** - Geolocation

Total cost: **$0/month**

---

## 💡 Advanced Configuration

### Rate Limiting

The application automatically handles rate limiting. Configure delays in settings:

```yaml
osint:
  rate_limit_delay: 0.5  # seconds between requests
  max_concurrent_requests: 50
```

### Caching

Results are cached to reduce API calls:

- Default cache TTL: 1 hour
- Configurable per source
- Cache stored in `~/.hydrarecon/cache.db`

### Proxy Support

Route API calls through proxy/Tor:

```yaml
scan:
  proxy: "socks5://127.0.0.1:9050"
  tor_enabled: true
```

---

## 🔒 Security Best Practices

1. **Never commit API keys** to version control
2. **Use environment variables** in production
3. **Rotate keys** regularly
4. **Monitor usage** for unusual activity
5. **Use read-only keys** when available

---

## 📞 Support

For API-specific issues:
- Check the provider's documentation
- Verify rate limits haven't been exceeded
- Ensure keys are correctly formatted
- Check network connectivity

For HydraRecon issues:
- GitHub Issues: https://github.com/SAMIAM717/predator1

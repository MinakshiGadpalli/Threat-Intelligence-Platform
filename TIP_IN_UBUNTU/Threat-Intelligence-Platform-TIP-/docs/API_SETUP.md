# 🔑 Free API Registration Guide

All APIs used in this project have **free tiers** that cover development and light production use.

---

## 1. AlienVault OTX (Open Threat Exchange)
- **URL**: https://otx.alienvault.com
- **Sign up**: Free account, no credit card
- **Free tier**: Unlimited API access to subscribed pulses
- **Steps**:
  1. Register at https://otx.alienvault.com/accounts/register
  2. Go to Settings → API Key
  3. Copy your API key into `config/config.yaml` under `apis.alienvault_otx.api_key`
  4. Subscribe to some threat pulses (search for "malware", "tor-exit-nodes", "APT")

---

## 2. AbuseIPDB
- **URL**: https://www.abuseipdb.com
- **Sign up**: Free account
- **Free tier**: 1,000 API requests/day (resets daily)
- **Steps**:
  1. Register at https://www.abuseipdb.com/register
  2. Go to Account → API → Create Key
  3. Copy into `config/config.yaml` under `apis.abuseipdb.api_key`
  4. The blacklist endpoint returns up to 10,000 IPs per request on free tier

---

## 3. URLhaus (No Key Required!)
- **URL**: https://urlhaus.abuse.ch
- **Sign up**: Not required
- **Free tier**: Unlimited, completely open API
- **Steps**: Nothing to do — it works out of the box!

---

## 4. VirusTotal (Optional)
- **URL**: https://www.virustotal.com
- **Sign up**: Free account
- **Free tier**: 500 requests/day, 4 requests/minute
- **Steps**:
  1. Register at https://www.virustotal.com/gui/join-us
  2. Go to your profile → API Key
  3. Copy into `config/config.yaml` under `apis.virustotal.api_key`
  4. Set `enabled: true`

---

## Quick Config Example

After registering, your `config/config.yaml` should look like:

```yaml
apis:
  alienvault_otx:
    api_key: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    enabled: true

  abuseipdb:
    api_key: "abc123def456abc123def456abc123def456abc123def456abc123"
    enabled: true

  urlhaus:
    enabled: true   # No key needed!
```

---

## Testing Your Keys

```bash
# Test AbuseIPDB
curl -G https://api.abuseipdb.com/api/v2/blacklist \
  -d confidenceMinimum=90 \
  -H "Key: YOUR_KEY" \
  -H "Accept: application/json" | head -c 500

# Test URLhaus (no key)
curl -d "limit=5" https://urlhaus-api.abuse.ch/v1/urls/recent/
```

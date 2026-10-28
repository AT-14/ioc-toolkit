# SOC IOC Extraction & Threat Intelligence Enrichment Toolkit

A lightweight Python command-line toolkit for extracting Indicators of Compromise (IOCs) from unstructured security text (such as raw email headers, phishing bodies, and analyst triage notes), defanging indicators for safe sharing, and enriching extracted indicators against the **VirusTotal v3** and **AbuseIPDB v2** APIs.

---

## Project Overview

During Security Operations Center (SOC) email and identity investigations, analysts routinely parse raw artifacts to collect network, host, and file indicators before querying external threat intelligence providers. This repository provides two connected command-line scripts that automate indicator collection, safe defanging, and reputation lookups while preserving analyst context and explicitly documenting intelligence limitations.

### Tools Included

1. **`ioc_extractor.py`**
   - Parses raw text strings (`-t`) or text files (`-f`) such as `.eml` bodies, email headers, or incident notes.
   - Extracts and deduplicates IPv4/IPv6 addresses, URLs, domains, email addresses, and file hashes.
   - Validates IP candidates with Python's `ipaddress` module and validates URL ports with `urllib.parse.urlsplit`.
   - Masks previously matched URLs, emails, and IP addresses before scanning for standalone domains to avoid duplicate or false-positive sub-matches, and filters out common file extensions (such as `.exe`, `.pdf`, `.ps1`, `.zip`).
   - Defangs indicators (`[.]`, `[:]`, `[@]`, `hxxp://`, `hxxps://`, `f[.]tp://`, `f[.]tps://`, `s[.]ftp://`) for safe handling in reports and tickets.
   - Outputs either a formatted console report or a structured JSON file (`-o`) ready for automated enrichment.

2. **`enrichment_tool.py`**
   - Consumes either the JSON file produced by `ioc_extractor.py` (`-i`) or a single raw/defanged indicator (`-s` with `-t`).
   - Validates single indicators using `ioc_extractor.ioc_extraction` before issuing external queries.
   - Automatically identifies private, loopback, link-local, and reserved non-routable IP addresses (RFC 1918, RFC 5737, loopback, IPv6 local), skipping external API calls for internal addresses and labeling them `Internal / Non-Routable`.
   - Queries **AbuseIPDB v2** (`/api/v2/check`) for public IPv4/IPv6 addresses (90-day window).
   - Queries **VirusTotal v3** (`/api/v3/files`, `/api/v3/domains`, `/api/v3/urls`) for file hashes, domains (including domains extracted from email addresses), and URLs.
   - Handles HTTP errors (`404`, `429`, `401`/`403`, `5xx`), network timeouts, connection failures, and malformed responses gracefully without crashing, writing structured JSON output (`-o`).

---

## Supported IOC Types

| Category | Extraction (`ioc_extractor.py`) | Defanging Format | Enrichment Provider (`enrichment_tool.py`) |
| :--- | :--- | :--- | :--- |
| **IPv4 / IPv6** | Standard IPv4, full/compressed IPv6, IPv4-mapped IPv6 (`::ffff:x.x.x.x`) | `198[.]51[.]100[.]88`, `2001[:]db8[:][:]1` | AbuseIPDB v2 (public IPs) / Local check (private/non-routable IPs) |
| **URLs** | `http://`, `https://`, `ftp://`, `ftps://`, `sftp://` (with ports, paths, queries, fragments) | `hxxp://`, `hxxps://`, `f[.]tp://`, `f[.]tps://`, `s[.]ftp://`, `[.]`, `[@]` | VirusTotal v3 (`/api/v3/urls/{base64_id}`) |
| **Domains** | Root domains, subdomains, IDN punycode (`xn--`), plus domains parsed from URLs and emails | `example[.]com` | VirusTotal v3 (`/api/v3/domains/{domain}`) |
| **Email Addresses** | Standard email addresses (preserves local-part case, normalizes domain to lowercase) | `user[@]example[.]com` | Domain component extracted and enriched via VirusTotal v3 |
| **File Hashes** | MD5 (32), SHA-1 (40), SHA-224 (56), SHA-256 (64), SHA-384 (96), SHA-512 (128) hex strings | Not applicable (hashes are non-clickable) | VirusTotal v3 (`/api/v3/files/{hash}`) |

---

## Architecture & Workflow

```text
Raw Email / Headers / Notes (text or file)
                  │
                  ▼
         ┌─────────────────┐
         │ ioc_extractor.py│
         └────────┬────────┘
                  │
      ┌───────────┴───────────┐
      ▼                       ▼
Console Report      Extracted IOC JSON (-o)
                              │
                              ▼
                     ┌──────────────────┐
                     │enrichment_tool.py│◄─── Single Indicator (-s & -t)
                     └────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
       Local RFC Check   AbuseIPDB v2   VirusTotal v3
       (Private/Local)   (Public IPs)  (URLs/Domains/Hashes)
              └───────────────┼───────────────┘
                              │
                              ▼
                  Enriched Report JSON (-o)
```

---

## Installation

### Prerequisites
- Python 3.9 or newer.
- A VirusTotal API key (free or premium tier).
- An AbuseIPDB API key (free or premium tier).

### Setup

1. Clone the repository and navigate to the project directory:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. (Recommended) Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows (PowerShell)
   .\.venv\Scripts\Activate.ps1
   # Linux / macOS
   source .venv/bin/activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## API-Key Configuration

`enrichment_tool.py` loads API credentials from environment variables or a local `.env` file using `python-dotenv`.

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and supply your API keys:
   ```ini
   VT_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   ```

Never commit your `.env` file to version control.

---

## CLI Usage Examples

### 1. Extracting IOCs

**Print a human-readable report to the console from an input file:**
```bash
python ioc_extractor.py -f sample_email.txt
```

**Extract IOCs directly from a raw text string:**
```bash
python ioc_extractor.py -t "Suspicious login from 185.220.101.42 to https://portal.example.com/login"
```

**Export extracted IOCs to a JSON file:**
```bash
python ioc_extractor.py -f sample_email.txt -o result.json
```

### 2. Enriching IOCs

**Enrich a full extractor JSON file:**
```bash
python enrichment_tool.py -i result.json -o final.json
```

**Enrich a single indicator (supports both raw and defanged indicators):**
```bash
# Enrich a single IP address
python enrichment_tool.py -s 185.220.101.42 -t ip -o ip_report.json

# Enrich a defanged domain
python enrichment_tool.py -s "auth-verify-login[.]net" -t domain -o domain_report.json

# Enrich a defanged URL
python enrichment_tool.py -s "hxxps://c2-srv[.]net/bin/agent[.]exe" -t url -o url_report.json

# Enrich a file hash
python enrichment_tool.py -s 356a192b7913b04c54574d18c28d46e6395428ab -t hash -o hash_report.json
```

---

## JSON Input & Output Structure

### Extractor Output (`ioc_extractor.py -o result.json`)

```json
{
    "summary": {
        "ip_count": 2,
        "url_count": 1,
        "domain_count": 2,
        "email_count": 1,
        "hash_count": 1
    },
    "iocs": {
        "ip_addresses": [
            {
                "raw": "185.220.101.42",
                "defanged": "185[.]220[.]101[.]42"
            },
            {
                "raw": "198.51.100.88",
                "defanged": "198[.]51[.]100[.]88"
            }
        ],
        "urls": [
            {
                "raw": "https://c2-srv.net/bin/agent.exe",
                "defanged": "hxxps://c2-srv[.]net/bin/agent[.]exe"
            }
        ],
        "domains": [
            {
                "raw": "c2-srv.net",
                "defanged": "c2-srv[.]net"
            },
            {
                "raw": "vendor-portal-update.com",
                "defanged": "vendor-portal-update[.]com"
            }
        ],
        "emails": [
            {
                "raw": "support-alert@vendor-portal-update.com",
                "defanged": "support-alert[@]vendor-portal-update[.]com"
            }
        ],
        "hashes": [
            {
                "type": "MD5",
                "value": "e11092ed90182a15ab836391e5935054"
            }
        ]
    }
}
```

### Enrichment Output (`enrichment_tool.py -i result.json -o final.json`)

In batch JSON mode (`-i`), the output contains a `metadata` object and an `enriched_iocs` object with `ip_addresses`, `urls`, `domains`, and `hashes` arrays. In single-indicator mode (`-s`), the output contains the single corresponding category key (`ip_addresses`, `domains`, `urls`, or `hashes`).

#### Verdict Terminology
- **VirusTotal (`hashes`, `domains`, `urls`)**:
  - `Flagged Malicious`: One or more engines reported the indicator as `malicious`.
  - `Flagged Suspicious`: Zero `malicious` detections, but one or more engines reported `suspicious`.
  - `No Detections`: Analyzed by at least one engine with zero `malicious` or `suspicious` flags.
  - `No Analysis Available`: HTTP 200 returned, but `last_analysis_stats` is missing or contains zero engine results.
  - `Unknown`: Indicator not present in the VirusTotal dataset (`HTTP 404`).
  - `Error (Rate Limited)` / `Error (HTTP <code>)` / `Error (Network Failure)` / `Error (Invalid API Response)`: Query failed due to rate limiting, HTTP error, network error, or malformed API payload.
- **AbuseIPDB (`ip_addresses`)**:
  - `High Reported Abuse`: `abuseConfidenceScore >= 50` (and `<= 100`).
  - `Moderate Reported Abuse`: `20 <= abuseConfidenceScore < 50`.
  - `Low Reported Abuse`: `0 <= abuseConfidenceScore < 20`.
  - `Unknown`: `abuseConfidenceScore` is missing or `null` in the response.
  - `Internal / Non-Routable`: Private, loopback, link-local, or reserved documentation IP skipped without external query.
  - `Error (Rate Limited)` / `Error (HTTP <code>)` / `Error (Network Failure)` / `Error (Invalid API Response)`: Query failed or returned an invalid score/payload.

---

## Testing Summary

Tests were applied during development and all passed.

## Known Limitations

1. **Public API Rate Limits**: Free VirusTotal API keys are limited to 4 requests per minute and 500 requests per day. `enrichment_tool.py` does not implement automatic sleep/backoff throttling between requests; large indicator batches on a free key may hit `HTTP 429` (`Error (Rate Limited)`).
2. **Pre-Defanged Input in Extractor**: `ioc_extractor.py` is designed to extract raw (fanged) indicators from source artifacts and defang them on output. Pre-defanged indicators in source text (such as `example[.]com` or `hxxps://...`) are not matched by `ioc_extractor.py`, though `enrichment_tool.py` supports defanged indicators directly.
3. **Hexadecimal String Collisions**: Any standalone 32, 40, 56, 64, 96, or 128-character hexadecimal token in source text (such as session IDs, Git commit SHA-1 hashes, or telemetry correlation IDs) matches the corresponding hash regular expression.
4. **URL Path File Extensions**: Standalone domain extraction filters out common file extensions (`.exe`, `.pdf`, `.ps1`, etc.), but unusual file extensions not in the exclusion set could be matched as standalone domains if written in `name.ext` format outside a URL.
5. **Reputation Lag**: Zero detections on VirusTotal (`No Detections`) or a low score on AbuseIPDB (`Low Reported Abuse`) do not guarantee an indicator is benign, particularly for newly registered phishing domains, compromised legitimate infrastructure, or newly compiled payloads.

---

## Security Considerations

- **Credential Protection**: API keys must only be stored in environment variables or a local `.env` file excluded via `.gitignore`. Never hardcode keys in scripts or commit `.env` files.
- **Data Privacy (OPSEC)**: `enrichment_tool.py` transmits queried IP addresses, domains, URLs, and file hashes to third-party APIs (VirusTotal and AbuseIPDB). Do not submit sensitive internal URLs (such as URLs containing session tokens, password reset links, or internal hostnames) without sanitizing confidential parameters first.
- **Safe Indicator Handling**: Use the defanged outputs generated by `ioc_extractor.py` when pasting indicators into tickets, emails, or documentation to prevent accidental clicks or automatic link preview requests.

---

## License

Released under the [MIT License](LICENSE).

---
name: ioc-extractor
description: "Extract and enrich Indicators of Compromise (IOCs) from any input — log files, alerts, emails, pastes, forensic tool output, threat intel reports, or raw text. Extracts IPs, domains, URLs, file hashes (MD5/SHA1/SHA256), email addresses, CVE IDs, Bitcoin/Ethereum addresses, MITRE ATT&CK technique IDs, and Windows-specific artifacts (registry paths, named pipes, service names). Enrichment via VirusTotal, AbuseIPDB, Shodan, OTX when API keys are available. Use this skill whenever the user mentions IOCs, indicators, observables, enrichment, reputation checks, or asks to 'extract indicators from', 'check this hash', 'enrich these IPs', 'defang/refang', or 'what IOCs are in this file'. Also triggers for triage workflows needing IOC context."
---

# IOC Extractor & Enrichment

## What this skill does

Takes any text input (log file, alert JSON, email, paste, forensic report) and:
1. Extracts all IOCs using battle-tested regex patterns
2. Deduplicates and classifies by type
3. Defangs output for safe sharing (configurable)
4. Enriches against threat intel APIs when keys are available
5. Outputs structured results (JSON, CSV, Markdown table, or STIX 2.1 bundle)

## Quick start

Run the extraction script on any input file:

```bash
python3 /path/to/skills/ioc-extractor/scripts/extract_iocs.py <input_file> [--enrich] [--format json|csv|markdown|stix] [--defang] [--output <output_file>]
```

Or pipe text directly:
```bash
cat suspicious_email.txt | python3 /path/to/skills/ioc-extractor/scripts/extract_iocs.py --stdin --enrich
```

## Extraction patterns

The script extracts the following indicator types with these regex patterns. When working without the script (e.g., analyzing text in context), apply these same patterns mentally:

| Type | Pattern | Examples |
|---|---|---|
| IPv4 | Standard dotted quad, excludes private/loopback by default | 203.0.113.50 |
| IPv6 | Full and compressed notation | 2001:db8::1 |
| Domain | FQDN with valid TLD, min 2 labels | evil.example[.]com |
| URL | http/https/ftp with path, query, fragment | hxxps://evil[.]com/payload |
| MD5 | 32 hex chars (case-insensitive) | d41d8cd98f00b204e9800998ecf8427e |
| SHA1 | 40 hex chars | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA256 | 64 hex chars | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| Email | Standard RFC 5322 pattern | attacker@evil.com |
| CVE | CVE-YYYY-NNNNN+ | CVE-2024-12345 |
| ATT&CK | T####(.###)? pattern | T1059.001 |
| Registry | HKLM/HKCU/HKU/HKCR paths | HKLM\Software\Microsoft\Windows\CurrentVersion\Run |
| Named pipe | \\.\pipe\ paths | \\.\pipe\evil_pipe |
| Bitcoin | 1/3/bc1 addresses | 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa |
| Ethereum | 0x + 40 hex chars | 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD |
| JARM | 62 hex chars | 07d14d16d21d21d07c42d41d00041d... |

## Handling defanged input

The extractor automatically refangs common defanging patterns before extraction:
- `hxxp` → `http`, `hxxps` → `https`
- `[.]` → `.`, `[:]` → `:`
- `[at]` / `[@]` → `@`
- `[/]` → `/`
- Dot-separated octets: `192[.]168[.]1[.]1`

## Enrichment

When `--enrich` is passed, the script checks for API keys as environment variables and enriches IOCs against available services:

| Service | Env Variable | IOC Types | Data Returned |
|---|---|---|---|
| VirusTotal | `VT_API_KEY` | hashes, domains, IPs, URLs | detection ratio, first/last seen, tags |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IPs | confidence score, abuse reports, ISP/country |
| Shodan | `SHODAN_API_KEY` | IPs | open ports, services, vulns, geo |
| OTX (AlienVault) | `OTX_API_KEY` | all types | pulse count, tags, related indicators |
| GreyNoise | `GREYNOISE_API_KEY` | IPs | classification (benign/malicious/unknown), noise status |

Rate limiting is enforced: VT free tier = 4 req/min, AbuseIPDB = 1000/day. The script uses exponential backoff and caches results to `.ioc_cache.json` to avoid repeated lookups within the same investigation.

## Output formats

**JSON** (default): Structured array with IOC type, value, defanged form, and enrichment data.

**CSV**: Flat table suitable for SIEM import or spreadsheet analysis.

**Markdown**: Human-readable table for reports and Confluence/wiki paste.

**STIX 2.1**: Bundle with proper SDO types (indicator, malware, infrastructure) and SROs for relationships. Suitable for MISP/OpenCTI import.

## Integration with other DFIR skills

The IOC extractor's JSON output is designed to chain with:
- **windows-artifact-triage**: Extract IOCs from EZTools CSV, correlate hashes against VT
- **log-timeline-correlator**: Enrich IPs/domains found in timeline events
- **yara-rule-generator**: Feed extracted hashes/strings as seed indicators for rule creation

## When NOT to use this skill

- If the user just wants to know what a single hash is → use web search against VT directly
- If the user needs full malware analysis → this extracts IOCs from reports, it doesn't analyze binaries
- If the user wants to write detection rules from IOCs → chain this skill's output into yara-rule-generator

## Script dependencies

```bash
pip install requests tldextract stix2 --break-system-packages
```

The script handles missing optional dependencies gracefully — enrichment is skipped if `requests` is unavailable, STIX output falls back to JSON if `stix2` is missing.

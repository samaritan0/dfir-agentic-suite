#!/usr/bin/env python3
"""
IOC Extractor & Enrichment Engine
Extracts Indicators of Compromise from any text input with optional threat intel enrichment.
Part of the DFIR Skills Suite for Claude.
"""

import re
import sys
import json
import csv
import hashlib
import os
import time
import argparse
from collections import defaultdict
from pathlib import Path
from io import StringIO

# ─── Regex Patterns ──────────────────────────────────────────────────────────

# Refanging patterns (applied before extraction)
REFANG_MAP = [
    (re.compile(r'hxxps?', re.I), lambda m: m.group().replace('xx', 'tt')),
    (re.compile(r'\[(\.|dot)\]', re.I), '.'),
    (re.compile(r'\[:\]'), ':'),
    (re.compile(r'\[at\]|\[@\]', re.I), '@'),
    (re.compile(r'\[/\]'), '/'),
    (re.compile(r'\(dot\)', re.I), '.'),
]

# IOC extraction patterns
PATTERNS = {
    'ipv4': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    ),
    'ipv6': re.compile(
        r'(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
        r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
        r'::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))'
    ),
    'md5': re.compile(r'\b[0-9a-fA-F]{32}\b'),
    'sha1': re.compile(r'\b[0-9a-fA-F]{40}\b'),
    'sha256': re.compile(r'\b[0-9a-fA-F]{64}\b'),
    'email': re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    ),
    'cve': re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I),
    'url': re.compile(
        r'https?://[^\s<>"\')\]}{|\\^`]+', re.I
    ),
    'domain': re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'{1,10}[a-zA-Z]{2,63}\b'
    ),
    'mitre_attack': re.compile(r'\bT\d{4}(?:\.\d{3})?\b'),
    'registry_path': re.compile(
        r'\b(?:HKLM|HKCU|HKU|HKCR|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|'
        r'HKEY_USERS|HKEY_CLASSES_ROOT)\\[^\s,;"\']+'
    ),
    'named_pipe': re.compile(r'\\\\\.\\pipe\\[^\s,;"\']+'),
    'bitcoin': re.compile(r'\b(?:1|3)[1-9A-HJ-NP-Za-km-z]{25,34}\b|bc1[a-zA-HJ-NP-Z0-9]{25,90}\b'),
    'ethereum': re.compile(r'\b0x[0-9a-fA-F]{40}\b'),
    'jarm': re.compile(r'\b[0-9a-fA-F]{62}\b'),
}

# Private/reserved IP ranges to exclude
PRIVATE_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.'),
    re.compile(r'^169\.254\.'),
    re.compile(r'^224\.'),
    re.compile(r'^255\.'),
]

# Common false-positive domains to skip
FP_DOMAINS = {
    'aka.ms', 'schemas.microsoft.com', 'www.w3.org', 'purl.org',
    'xmlns.com', 'example.com', 'example.org', 'example.net',
    'localhost', 'schema.org', 'json-schema.org',
}

# TLDs that are actually file extensions in log context
NON_TLDS = {'exe', 'dll', 'sys', 'tmp', 'log', 'dat', 'bak', 'old', 'cfg'}


def refang(text: str) -> str:
    """Refang defanged indicators in text."""
    for pattern, replacement in REFANG_MAP:
        if callable(replacement):
            text = pattern.sub(replacement, text)
        else:
            text = pattern.sub(replacement, text)
    return text


def defang_ioc(ioc_type: str, value: str) -> str:
    """Defang an IOC value for safe sharing."""
    if ioc_type in ('url',):
        value = value.replace('http', 'hxxp', 1)
    if ioc_type in ('domain', 'url', 'email', 'ipv4'):
        # Defang first dot only for IPs/domains, all dots for URLs
        if ioc_type == 'ipv4':
            parts = value.split('.')
            value = '[.]'.join(parts)
        elif ioc_type in ('domain', 'url'):
            value = value.replace('.', '[.]', 1)
    return value


def is_private_ip(ip: str) -> bool:
    """Check if IP is in a private/reserved range."""
    return any(r.match(ip) for r in PRIVATE_RANGES)


def is_valid_domain(domain: str) -> bool:
    """Filter out false-positive domains."""
    if domain.lower() in FP_DOMAINS:
        return False
    tld = domain.rsplit('.', 1)[-1].lower()
    if tld in NON_TLDS:
        return False
    # Must have at least 2 labels
    if domain.count('.') < 1:
        return False
    return True


def is_likely_hash(value: str, hash_type: str) -> bool:
    """Heuristic: real hashes have mixed case or digits; all-alpha strings are likely words."""
    if hash_type == 'jarm':
        return True  # JARM fingerprints are always hex
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    return has_digit and has_alpha


def extract_iocs(text: str, include_private_ips: bool = False) -> dict:
    """
    Extract all IOCs from text.
    Returns dict of {ioc_type: [list of unique values]}
    """
    # Refang first
    clean_text = refang(text)

    results = defaultdict(list)
    seen = set()

    # Extract URLs first (they contain domains and IPs we should skip)
    url_matches = set()
    for m in PATTERNS['url'].finditer(clean_text):
        url = m.group().rstrip('.,;:)]}>')
        if url not in seen:
            seen.add(url)
            url_matches.add(url)
            results['url'].append(url)

    # Track which IPs/domains are already in URLs
    url_text = ' '.join(url_matches)

    for ioc_type, pattern in PATTERNS.items():
        if ioc_type == 'url':
            continue  # Already processed

        for m in pattern.finditer(clean_text):
            value = m.group()

            # Dedup
            if value in seen:
                continue

            # Type-specific filtering
            if ioc_type == 'ipv4':
                if not include_private_ips and is_private_ip(value):
                    continue
                # Skip IPs already captured in URLs
                if value in url_text:
                    continue

            elif ioc_type == 'domain':
                if not is_valid_domain(value):
                    continue
                # Skip domains already in URLs
                if any(value in u for u in url_matches):
                    continue

            elif ioc_type in ('md5', 'sha1', 'sha256', 'jarm'):
                if not is_likely_hash(value, ioc_type):
                    continue
                # SHA256 subsumes SHA1 subsumes MD5 — check longest first
                if ioc_type == 'md5' and (value in ' '.join(results.get('sha1', [])) or
                                           value in ' '.join(results.get('sha256', []))):
                    continue

            seen.add(value)
            results[ioc_type].append(value)

    return dict(results)


# ─── Enrichment ──────────────────────────────────────────────────────────────

class ThreatIntelEnricher:
    """Enrich IOCs against threat intelligence APIs."""

    def __init__(self, cache_file: str = '.ioc_cache.json'):
        self.cache_file = Path(cache_file)
        self.cache = self._load_cache()
        self.apis = {}

        # Detect available API keys
        if os.environ.get('VT_API_KEY'):
            self.apis['virustotal'] = os.environ['VT_API_KEY']
        if os.environ.get('ABUSEIPDB_API_KEY'):
            self.apis['abuseipdb'] = os.environ['ABUSEIPDB_API_KEY']
        if os.environ.get('SHODAN_API_KEY'):
            self.apis['shodan'] = os.environ['SHODAN_API_KEY']
        if os.environ.get('OTX_API_KEY'):
            self.apis['otx'] = os.environ['OTX_API_KEY']
        if os.environ.get('GREYNOISE_API_KEY'):
            self.apis['greynoise'] = os.environ['GREYNOISE_API_KEY']

    def _load_cache(self) -> dict:
        if self.cache_file.exists():
            try:
                return json.loads(self.cache_file.read_text())
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_cache(self):
        try:
            self.cache_file.write_text(json.dumps(self.cache, indent=2))
        except IOError:
            pass

    def _cache_key(self, service: str, ioc: str) -> str:
        return f"{service}:{ioc}"

    def _rate_limit(self, service: str):
        """Simple rate limiter."""
        delays = {'virustotal': 15, 'abuseipdb': 1, 'shodan': 1, 'otx': 0.5, 'greynoise': 1}
        time.sleep(delays.get(service, 1))

    def enrich_ip(self, ip: str) -> dict:
        """Enrich an IP against all available services."""
        result = {'ip': ip, 'enrichment': {}}

        try:
            import requests
        except ImportError:
            result['enrichment']['error'] = 'requests library not installed'
            return result

        # VirusTotal
        if 'virustotal' in self.apis:
            ck = self._cache_key('vt_ip', ip)
            if ck in self.cache:
                result['enrichment']['virustotal'] = self.cache[ck]
            else:
                try:
                    self._rate_limit('virustotal')
                    resp = requests.get(
                        f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                        headers={'x-apikey': self.apis['virustotal']},
                        timeout=10
                    )
                    if resp.status_code == 200:
                        data = resp.json().get('data', {}).get('attributes', {})
                        vt_result = {
                            'malicious': data.get('last_analysis_stats', {}).get('malicious', 0),
                            'suspicious': data.get('last_analysis_stats', {}).get('suspicious', 0),
                            'harmless': data.get('last_analysis_stats', {}).get('harmless', 0),
                            'country': data.get('country', 'unknown'),
                            'as_owner': data.get('as_owner', 'unknown'),
                            'reputation': data.get('reputation', 0),
                        }
                        result['enrichment']['virustotal'] = vt_result
                        self.cache[ck] = vt_result
                except Exception as e:
                    result['enrichment']['virustotal_error'] = str(e)

        # AbuseIPDB
        if 'abuseipdb' in self.apis:
            ck = self._cache_key('abuseipdb', ip)
            if ck in self.cache:
                result['enrichment']['abuseipdb'] = self.cache[ck]
            else:
                try:
                    self._rate_limit('abuseipdb')
                    resp = requests.get(
                        'https://api.abuseipdb.com/api/v2/check',
                        headers={'Key': self.apis['abuseipdb'], 'Accept': 'application/json'},
                        params={'ipAddress': ip, 'maxAgeInDays': 90},
                        timeout=10
                    )
                    if resp.status_code == 200:
                        data = resp.json().get('data', {})
                        abuse_result = {
                            'confidence_score': data.get('abuseConfidenceScore', 0),
                            'total_reports': data.get('totalReports', 0),
                            'isp': data.get('isp', 'unknown'),
                            'country': data.get('countryCode', 'unknown'),
                            'usage_type': data.get('usageType', 'unknown'),
                            'is_tor': data.get('isTor', False),
                        }
                        result['enrichment']['abuseipdb'] = abuse_result
                        self.cache[ck] = abuse_result
                except Exception as e:
                    result['enrichment']['abuseipdb_error'] = str(e)

        # GreyNoise
        if 'greynoise' in self.apis:
            ck = self._cache_key('greynoise', ip)
            if ck in self.cache:
                result['enrichment']['greynoise'] = self.cache[ck]
            else:
                try:
                    self._rate_limit('greynoise')
                    resp = requests.get(
                        f'https://api.greynoise.io/v3/community/{ip}',
                        headers={'key': self.apis['greynoise']},
                        timeout=10
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        gn_result = {
                            'classification': data.get('classification', 'unknown'),
                            'noise': data.get('noise', False),
                            'riot': data.get('riot', False),
                            'name': data.get('name', ''),
                        }
                        result['enrichment']['greynoise'] = gn_result
                        self.cache[ck] = gn_result
                except Exception as e:
                    result['enrichment']['greynoise_error'] = str(e)

        self._save_cache()
        return result

    def enrich_hash(self, file_hash: str) -> dict:
        """Enrich a file hash against VirusTotal."""
        result = {'hash': file_hash, 'enrichment': {}}

        if 'virustotal' not in self.apis:
            return result

        try:
            import requests
        except ImportError:
            return result

        ck = self._cache_key('vt_hash', file_hash)
        if ck in self.cache:
            result['enrichment']['virustotal'] = self.cache[ck]
            return result

        try:
            self._rate_limit('virustotal')
            resp = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers={'x-apikey': self.apis['virustotal']},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                vt_result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'type_description': data.get('type_description', ''),
                    'popular_threat_classification': data.get('popular_threat_classification', {}),
                    'names': data.get('names', [])[:5],
                    'first_submission_date': data.get('first_submission_date', ''),
                    'tags': data.get('tags', [])[:10],
                }
                result['enrichment']['virustotal'] = vt_result
                self.cache[ck] = vt_result
            elif resp.status_code == 404:
                result['enrichment']['virustotal'] = {'status': 'not_found'}
                self.cache[ck] = {'status': 'not_found'}
        except Exception as e:
            result['enrichment']['virustotal_error'] = str(e)

        self._save_cache()
        return result

    def enrich_domain(self, domain: str) -> dict:
        """Enrich a domain against VirusTotal."""
        result = {'domain': domain, 'enrichment': {}}

        if 'virustotal' not in self.apis:
            return result

        try:
            import requests
        except ImportError:
            return result

        ck = self._cache_key('vt_domain', domain)
        if ck in self.cache:
            result['enrichment']['virustotal'] = self.cache[ck]
            return result

        try:
            self._rate_limit('virustotal')
            resp = requests.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers={'x-apikey': self.apis['virustotal']},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                vt_result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'registrar': data.get('registrar', ''),
                    'creation_date': data.get('creation_date', ''),
                    'reputation': data.get('reputation', 0),
                    'categories': data.get('categories', {}),
                }
                result['enrichment']['virustotal'] = vt_result
                self.cache[ck] = vt_result
        except Exception as e:
            result['enrichment']['virustotal_error'] = str(e)

        self._save_cache()
        return result

    def enrich_all(self, iocs: dict) -> list:
        """Enrich all extracted IOCs. Returns list of enrichment results."""
        enriched = []
        for ioc_type, values in iocs.items():
            for value in values:
                entry = {'type': ioc_type, 'value': value, 'defanged': defang_ioc(ioc_type, value)}

                if ioc_type == 'ipv4':
                    entry.update(self.enrich_ip(value))
                elif ioc_type in ('md5', 'sha1', 'sha256'):
                    entry.update(self.enrich_hash(value))
                elif ioc_type == 'domain':
                    entry.update(self.enrich_domain(value))
                else:
                    entry['enrichment'] = {}

                enriched.append(entry)

        return enriched


# ─── Output Formatters ───────────────────────────────────────────────────────

def format_json(iocs: dict, enriched: list = None) -> str:
    """Format as JSON."""
    if enriched:
        return json.dumps(enriched, indent=2, default=str)

    output = []
    for ioc_type, values in iocs.items():
        for v in values:
            output.append({
                'type': ioc_type,
                'value': v,
                'defanged': defang_ioc(ioc_type, v),
            })
    return json.dumps(output, indent=2)


def format_csv(iocs: dict, enriched: list = None) -> str:
    """Format as CSV."""
    buf = StringIO()
    writer = csv.writer(buf)

    if enriched:
        writer.writerow(['type', 'value', 'defanged', 'vt_malicious', 'vt_suspicious',
                         'abuse_score', 'country', 'tags'])
        for e in enriched:
            vt = e.get('enrichment', {}).get('virustotal', {})
            abuse = e.get('enrichment', {}).get('abuseipdb', {})
            writer.writerow([
                e['type'], e['value'], e.get('defanged', ''),
                vt.get('malicious', ''), vt.get('suspicious', ''),
                abuse.get('confidence_score', ''),
                vt.get('country', abuse.get('country', '')),
                ';'.join(vt.get('tags', [])),
            ])
    else:
        writer.writerow(['type', 'value', 'defanged'])
        for ioc_type, values in iocs.items():
            for v in values:
                writer.writerow([ioc_type, v, defang_ioc(ioc_type, v)])

    return buf.getvalue()


def format_markdown(iocs: dict, enriched: list = None) -> str:
    """Format as Markdown table."""
    lines = ['# IOC Extraction Report', '', f'**Total unique IOCs: {sum(len(v) for v in iocs.values())}**', '']

    # Summary
    lines.append('## Summary by Type')
    lines.append('')
    lines.append('| Type | Count |')
    lines.append('|---|---|')
    for ioc_type, values in sorted(iocs.items()):
        lines.append(f'| {ioc_type} | {len(values)} |')

    lines.append('')
    lines.append('## Indicators')

    if enriched:
        lines.append('')
        lines.append('| Type | Value | VT Malicious | Abuse Score | Country |')
        lines.append('|---|---|---|---|---|')
        for e in enriched:
            vt = e.get('enrichment', {}).get('virustotal', {})
            abuse = e.get('enrichment', {}).get('abuseipdb', {})
            vt_mal = vt.get('malicious', '-')
            abuse_score = abuse.get('confidence_score', '-')
            country = vt.get('country', abuse.get('country', '-'))
            lines.append(f'| {e["type"]} | `{e.get("defanged", e["value"])}` | {vt_mal} | {abuse_score} | {country} |')
    else:
        lines.append('')
        lines.append('| Type | Value (defanged) |')
        lines.append('|---|---|')
        for ioc_type, values in sorted(iocs.items()):
            for v in values:
                lines.append(f'| {ioc_type} | `{defang_ioc(ioc_type, v)}` |')

    return '\n'.join(lines)


def format_stix(iocs: dict) -> str:
    """Format as STIX 2.1 bundle (requires stix2 library)."""
    try:
        from stix2 import Bundle, Indicator, Identity
        from datetime import datetime, timezone

        identity = Identity(
            name="DFIR Claude Skill",
            identity_class="system"
        )

        indicators = []
        for ioc_type, values in iocs.items():
            for v in values:
                pattern_map = {
                    'ipv4': f"[ipv4-addr:value = '{v}']",
                    'ipv6': f"[ipv6-addr:value = '{v}']",
                    'domain': f"[domain-name:value = '{v}']",
                    'url': f"[url:value = '{v}']",
                    'md5': f"[file:hashes.MD5 = '{v}']",
                    'sha1': f"[file:hashes.'SHA-1' = '{v}']",
                    'sha256': f"[file:hashes.'SHA-256' = '{v}']",
                    'email': f"[email-addr:value = '{v}']",
                }
                stix_pattern = pattern_map.get(ioc_type)
                if stix_pattern:
                    indicators.append(Indicator(
                        name=f"{ioc_type}: {v}",
                        pattern_type="stix",
                        pattern=stix_pattern,
                        valid_from=datetime.now(timezone.utc),
                        created_by_ref=identity.id,
                        labels=[ioc_type, "dfir-extraction"],
                    ))

        bundle = Bundle(objects=[identity] + indicators)
        return bundle.serialize(pretty=True)

    except ImportError:
        return json.dumps({"error": "stix2 library required for STIX output. Install: pip install stix2"})


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Extract and enrich IOCs from any text input.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious_email.txt
  %(prog)s alert.json --enrich --format csv --output iocs.csv
  cat access.log | %(prog)s --stdin --enrich --format markdown
  %(prog)s report.txt --format stix --output indicators.json
        """
    )
    parser.add_argument('input_file', nargs='?', help='Input file to extract IOCs from')
    parser.add_argument('--stdin', action='store_true', help='Read from stdin')
    parser.add_argument('--enrich', action='store_true', help='Enrich IOCs via threat intel APIs')
    parser.add_argument('--format', choices=['json', 'csv', 'markdown', 'stix'], default='json',
                        help='Output format (default: json)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--defang', action='store_true', help='Defang all IOCs in output')
    parser.add_argument('--include-private', action='store_true', help='Include private/RFC1918 IPs')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress progress messages')

    args = parser.parse_args()

    # Read input
    if args.stdin:
        text = sys.stdin.read()
    elif args.input_file:
        try:
            text = Path(args.input_file).read_text(errors='replace')
        except FileNotFoundError:
            print(f"Error: File not found: {args.input_file}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    if not args.quiet:
        print(f"[*] Analyzing {len(text)} characters of input...", file=sys.stderr)

    # Extract
    iocs = extract_iocs(text, include_private_ips=args.include_private)

    total = sum(len(v) for v in iocs.values())
    if not args.quiet:
        print(f"[+] Found {total} unique IOCs across {len(iocs)} types", file=sys.stderr)
        for ioc_type, values in sorted(iocs.items()):
            print(f"    {ioc_type}: {len(values)}", file=sys.stderr)

    # Enrich
    enriched = None
    if args.enrich:
        enricher = ThreatIntelEnricher()
        if enricher.apis:
            if not args.quiet:
                print(f"[*] Enriching via: {', '.join(enricher.apis.keys())}", file=sys.stderr)
            enriched = enricher.enrich_all(iocs)
            if not args.quiet:
                print(f"[+] Enrichment complete", file=sys.stderr)
        else:
            if not args.quiet:
                print("[!] No API keys found. Set VT_API_KEY, ABUSEIPDB_API_KEY, etc.", file=sys.stderr)

    # Format output
    if args.format == 'json':
        output = format_json(iocs, enriched)
    elif args.format == 'csv':
        output = format_csv(iocs, enriched)
    elif args.format == 'markdown':
        output = format_markdown(iocs, enriched)
    elif args.format == 'stix':
        output = format_stix(iocs)

    # Write output
    if args.output:
        Path(args.output).write_text(output)
        if not args.quiet:
            print(f"[+] Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()

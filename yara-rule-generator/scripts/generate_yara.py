#!/usr/bin/env python3
"""
YARA Rule Generator
Generates production-quality YARA rules from behavioral descriptions, strings, IOCs, and PE analysis.
Part of the DFIR Skills Suite for Claude.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ─── String Filtering ────────────────────────────────────────────────────────

# Common benign strings to filter out during string-based rule generation
NOISE_STRINGS = {
    'this program cannot be run', 'rich', '.text', '.data', '.rdata', '.rsrc',
    '.reloc', '.bss', 'msvcrt', 'kernel32', 'ntdll', 'GetProcAddress',
    'LoadLibraryA', 'GetModuleHandleA', 'ExitProcess', 'VirtualProtect',
    'CloseHandle', 'CreateFileA', 'ReadFile', 'WriteFile', 'GetLastError',
    'SetLastError', 'GetCurrentProcess', 'GetCurrentThread',
    'HeapAlloc', 'HeapFree', 'GetProcessHeap',
    'lstrcpy', 'lstrlen', 'lstrcmp', 'wsprintf',
    'http://', 'https://', 'ftp://',  # too generic alone
    'microsoft', 'windows', 'system32',
    '<assembly', '<assemblyIdentity', 'manifestVersion',
    '<?xml', 'utf-8', 'xmlns',
}

# Interesting string categories
INTERESTING_PATTERNS = {
    'network': [
        re.compile(r'https?://[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}(/[^\s]*)?'),
        re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b'),
        re.compile(r'Mozilla/\d'),
        re.compile(r'User-Agent:'),
        re.compile(r'POST\s+/'),
        re.compile(r'GET\s+/'),
        re.compile(r'Content-Type:'),
        re.compile(r'\b[a-z0-9]+\.(onion|bit|i2p)\b'),
    ],
    'crypto': [
        re.compile(r'AES|RSA|RC4|Blowfish|ChaCha', re.I),
        re.compile(r'CryptEncrypt|BCryptEncrypt|CryptDecrypt'),
        re.compile(r'-----BEGIN (RSA |EC )?PUBLIC KEY-----'),
        re.compile(r'-----BEGIN CERTIFICATE-----'),
    ],
    'persistence': [
        re.compile(r'CurrentVersion\\Run', re.I),
        re.compile(r'schtasks\s', re.I),
        re.compile(r'sc\s+(create|config)', re.I),
        re.compile(r'HKLM\\SYSTEM\\CurrentControlSet\\Services'),
        re.compile(r'\\Start Menu\\Programs\\Startup', re.I),
        re.compile(r'wmic\s+.*subscription', re.I),
    ],
    'execution': [
        re.compile(r'cmd\.exe\s+/c', re.I),
        re.compile(r'powershell\s+.*-e(nc)?', re.I),
        re.compile(r'IEX\s*\(', re.I),
        re.compile(r'Invoke-(Expression|Command|WebRequest)', re.I),
        re.compile(r'FromBase64String'),
        re.compile(r'New-Object\s+System\.Net', re.I),
    ],
    'evasion': [
        re.compile(r'IsDebuggerPresent'),
        re.compile(r'CheckRemoteDebuggerPresent'),
        re.compile(r'NtQueryInformationProcess'),
        re.compile(r'OutputDebugString'),
        re.compile(r'vmware|virtualbox|qemu|xen|sandbox', re.I),
        re.compile(r'sleep\s*\(\s*\d{4,}', re.I),  # Long sleep
    ],
    'injection': [
        re.compile(r'VirtualAllocEx'),
        re.compile(r'WriteProcessMemory'),
        re.compile(r'CreateRemoteThread'),
        re.compile(r'NtCreateSection'),
        re.compile(r'NtMapViewOfSection'),
        re.compile(r'QueueUserAPC'),
        re.compile(r'SetWindowsHookEx'),
    ],
    'credential': [
        re.compile(r'mimikatz', re.I),
        re.compile(r'sekurlsa', re.I),
        re.compile(r'lsass', re.I),
        re.compile(r'SAM\s+database', re.I),
        re.compile(r'CredentialManager'),
        re.compile(r'dpapi', re.I),
    ],
    'exfil': [
        re.compile(r'rclone', re.I),
        re.compile(r'mega\.(nz|co)', re.I),
        re.compile(r'ngrok', re.I),
        re.compile(r'pastebin', re.I),
        re.compile(r'transfer\.sh', re.I),
    ],
    'mutex': [
        re.compile(r'Global\\[A-Za-z0-9_\-]{8,}'),
        re.compile(r'Local\\[A-Za-z0-9_\-]{8,}'),
    ],
    'pdb': [
        re.compile(r'[A-Z]:\\.*\.pdb'),
    ],
}

# Suspicious import combinations
SUSPICIOUS_IMPORT_COMBOS = {
    'process_injection': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
    'process_hollowing': ['CreateProcessA', 'NtUnmapViewOfSection', 'VirtualAllocEx', 'WriteProcessMemory'],
    'dll_injection': ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'LoadLibraryA'],
    'keylogger': ['SetWindowsHookExA', 'GetAsyncKeyState', 'GetKeyState'],
    'screen_capture': ['BitBlt', 'GetDC', 'CreateCompatibleBitmap'],
    'file_encryption': ['CryptAcquireContextA', 'CryptGenKey', 'CryptEncrypt', 'CryptDestroyKey'],
    'network_comms': ['WSAStartup', 'connect', 'send', 'recv', 'InternetOpenA'],
    'privilege_escalation': ['AdjustTokenPrivileges', 'LookupPrivilegeValueA', 'OpenProcessToken'],
}

# ─── Behavioral Description Parser ──────────────────────────────────────────

BEHAVIOR_TO_YARA = {
    'drops files': {'strings': ['\\\\Temp\\\\', '\\\\AppData\\\\', 'CreateFileA', 'WriteFile']},
    'contacts c2': {'strings': ['http://', 'https://', 'InternetOpenA', 'HttpSendRequestA', 'WinHttpOpen']},
    'encrypts files': {'imports': ['CryptEncrypt', 'BCryptEncrypt', 'CryptAcquireContext'],
                       'strings': ['.encrypted', '.locked', '.crypt']},
    'ransomware': {'strings': ['YOUR FILES HAVE BEEN ENCRYPTED', 'bitcoin', 'ransom', 'decrypt',
                               '.onion', 'README', 'RECOVER', 'RESTORE']},
    'creates service': {'imports': ['CreateServiceA', 'CreateServiceW', 'OpenSCManagerA'],
                        'strings': ['sc create', 'New-Service']},
    'scheduled task': {'strings': ['schtasks', '/create', '/tn', '/tr', 'Register-ScheduledTask']},
    'registry persistence': {'strings': ['CurrentVersion\\\\Run', 'HKLM\\\\SOFTWARE', 'RegSetValueEx']},
    'process injection': {'imports': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']},
    'powershell': {'strings': ['powershell', '-enc', '-nop', '-w hidden', 'IEX', 'Invoke-Expression',
                               'FromBase64String', 'System.Net.WebClient', 'DownloadString']},
    'lateral movement': {'strings': ['psexec', '\\\\\\\\', 'admin$', 'IPC$', 'wmic', 'Invoke-WmiMethod']},
    'credential theft': {'strings': ['mimikatz', 'sekurlsa', 'lsass', 'procdump', 'comsvcs.dll']},
    'data exfiltration': {'strings': ['rclone', 'mega.nz', 'upload', 'POST /']},
    'anti-analysis': {'imports': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'],
                      'strings': ['vmware', 'virtualbox', 'sandbox']},
    'packed': {'modules': ['math'], 'condition_extra': 'math.entropy(0, filesize) > 7.0'},
    'tor': {'strings': ['.onion', 'tor2web', 'SOCKS5', '9050', '9150']},
    'keylogger': {'imports': ['SetWindowsHookExA', 'GetAsyncKeyState', 'GetKeyState'],
                  'strings': ['keylog', 'keystroke']},
    'wmi persistence': {'strings': ['__EventFilter', '__EventConsumer', '__FilterToConsumerBinding',
                                     'ActiveScriptEventConsumer', 'CommandLineEventConsumer']},
}


def parse_behavioral_description(description):
    """Parse natural language behavioral description into YARA components."""
    desc_lower = description.lower()
    strings = set()
    imports = set()
    modules = set()
    condition_extras = []
    tags = set()

    for behavior, components in BEHAVIOR_TO_YARA.items():
        if behavior in desc_lower:
            strings.update(components.get('strings', []))
            imports.update(components.get('imports', []))
            modules.update(components.get('modules', []))
            if 'condition_extra' in components:
                condition_extras.append(components['condition_extra'])
            tags.add(behavior.replace(' ', '_'))

    return {
        'strings': sorted(strings),
        'imports': sorted(imports),
        'modules': sorted(modules),
        'condition_extras': condition_extras,
        'tags': sorted(tags),
    }


# ─── String Analysis ─────────────────────────────────────────────────────────

def analyze_strings(strings_list):
    """Categorize and filter strings for rule generation."""
    categorized = defaultdict(list)
    filtered_count = 0

    for s in strings_list:
        s = s.strip()
        if not s or len(s) < 4:
            continue

        # Filter noise
        s_lower = s.lower()
        if any(noise in s_lower for noise in NOISE_STRINGS):
            filtered_count += 1
            continue

        # Categorize
        matched = False
        for category, patterns in INTERESTING_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(s):
                    categorized[category].append(s)
                    matched = True
                    break
            if matched:
                break

        if not matched and len(s) >= 8:
            # Check if it looks interesting (not pure common English)
            if (any(c in s for c in '\\/:@.') or  # Path-like
                re.search(r'[A-Z][a-z]+[A-Z]', s) or  # CamelCase
                re.search(r'[a-z]+_[a-z]+', s) or  # snake_case
                s.startswith('0x') or  # Hex
                re.search(r'\d+\.\d+\.\d+', s)):  # Version-like
                categorized['other'].append(s)

    return dict(categorized), filtered_count


# ─── Rule Builder ────────────────────────────────────────────────────────────

def escape_yara_string(s):
    """Escape a string for YARA rule inclusion."""
    return s.replace('\\', '\\\\').replace('"', '\\"')


def build_yara_rule(name, meta, strings_dict, condition, imports_list=None, modules=None, tags=None):
    """Build a complete YARA rule string."""
    lines = []

    # Imports
    if modules:
        for mod in sorted(set(modules)):
            lines.append(f'import "{mod}"')
        lines.append('')

    # Rule declaration
    tag_str = f' : {" ".join(tags)}' if tags else ''
    lines.append(f'rule {name}{tag_str}')
    lines.append('{')

    # Meta
    lines.append('    meta:')
    for key, value in meta.items():
        if isinstance(value, list):
            value = ', '.join(str(v) for v in value)
        lines.append(f'        {key} = "{escape_yara_string(str(value))}"')

    # Strings
    if strings_dict:
        lines.append('')
        lines.append('    strings:')
        for var_name, value in strings_dict.items():
            if isinstance(value, dict):
                # Hex pattern
                hex_str = value.get('hex', '')
                lines.append(f'        {var_name} = {{ {hex_str} }}')
            elif isinstance(value, tuple):
                # String with modifiers
                string_val, modifiers = value
                lines.append(f'        {var_name} = "{escape_yara_string(string_val)}" {modifiers}')
            else:
                lines.append(f'        {var_name} = "{escape_yara_string(value)}" nocase')

    # Condition
    lines.append('')
    lines.append('    condition:')
    for i, cond_line in enumerate(condition):
        prefix = '        ' if i == 0 else '        '
        lines.append(f'{prefix}{cond_line}')

    lines.append('}')
    return '\n'.join(lines)


# ─── Generation Modes ────────────────────────────────────────────────────────

def generate_from_behavioral(description, name, author='DFIR Claude Skill', reference='', severity='medium', mitre=''):
    """Generate YARA rule from behavioral description."""
    components = parse_behavioral_description(description)

    meta = {
        'description': description[:200],
        'author': author,
        'date': datetime.now().strftime('%Y-%m-%d'),
        'severity': severity,
    }
    if reference:
        meta['reference'] = reference
    if mitre:
        meta['mitre_attack'] = mitre
    elif components['tags']:
        # Auto-map some tags to ATT&CK
        tag_to_mitre = {
            'encrypts_files': 'T1486', 'ransomware': 'T1486',
            'process_injection': 'T1055', 'powershell': 'T1059.001',
            'creates_service': 'T1543.003', 'scheduled_task': 'T1053.005',
            'registry_persistence': 'T1547.001', 'credential_theft': 'T1003',
            'lateral_movement': 'T1021', 'keylogger': 'T1056.001',
            'wmi_persistence': 'T1546.003',
        }
        mitre_ids = [tag_to_mitre[t] for t in components['tags'] if t in tag_to_mitre]
        if mitre_ids:
            meta['mitre_attack'] = ', '.join(mitre_ids)

    # Build strings
    strings_dict = {}
    string_groups = defaultdict(list)

    for i, s in enumerate(components['strings']):
        # Categorize
        category = 'indicator'
        for cat, patterns in INTERESTING_PATTERNS.items():
            for p in patterns:
                if p.search(s):
                    category = cat
                    break

        string_groups[category].append(s)

    idx = 0
    for category, strs in string_groups.items():
        for s in strs:
            var_name = f'${category}_{idx}'
            # Determine modifiers
            modifiers = 'nocase'
            if '\\\\' in s:
                modifiers = 'nocase wide ascii'
            strings_dict[var_name] = (s, modifiers)
            idx += 1

    for i, imp in enumerate(components['imports']):
        strings_dict[f'$api_{i}'] = (imp, '')

    # Build condition
    condition = ['uint16(0) == 0x5A4D and', 'filesize < 5MB and']

    if len(strings_dict) <= 3:
        condition.append(f'all of them')
    elif len(strings_dict) <= 6:
        condition.append(f'3 of them')
    else:
        # Group-based condition
        groups = set()
        for var_name in strings_dict:
            prefix = var_name.split('_')[0]
            groups.add(prefix)
        group_conds = []
        for g in sorted(groups):
            group_conds.append(f'1 of ({g}_*)')
        condition.append('(' + ' and\n            '.join(group_conds) + ')')

    for extra in components.get('condition_extras', []):
        condition[-1] += ' and'
        condition.append(extra)

    return build_yara_rule(
        name=name,
        meta=meta,
        strings_dict=strings_dict,
        condition=condition,
        modules=components.get('modules'),
        tags=components.get('tags'),
    )


def generate_from_strings(strings_file, name, author='DFIR Claude Skill', min_length=6):
    """Generate YARA rule from extracted strings."""
    with open(strings_file, 'r', errors='replace') as f:
        raw_strings = [l.strip() for l in f if len(l.strip()) >= min_length]

    categorized, filtered = analyze_strings(raw_strings)

    if not categorized:
        return f"// No interesting strings found in {strings_file} ({filtered} filtered as noise)"

    meta = {
        'description': f'Rule generated from {len(raw_strings)} extracted strings ({filtered} noise filtered)',
        'author': author,
        'date': datetime.now().strftime('%Y-%m-%d'),
        'severity': 'medium',
        'total_strings_analyzed': str(len(raw_strings)),
        'unique_interesting': str(sum(len(v) for v in categorized.values())),
    }

    strings_dict = {}
    idx = 0
    for category, strs in categorized.items():
        # Take top strings per category (avoid oversized rules)
        for s in strs[:10]:
            modifiers = 'nocase'
            if any(c in s for c in '\\/:'):
                modifiers = 'nocase wide ascii'
            strings_dict[f'${category}_{idx}'] = (s, modifiers)
            idx += 1

    # Condition based on coverage
    total_strings = len(strings_dict)
    threshold = max(2, total_strings // 3)

    condition = [
        'uint16(0) == 0x5A4D and',
        'filesize < 10MB and',
        f'{threshold} of them',
    ]

    return build_yara_rule(
        name=name,
        meta=meta,
        strings_dict=strings_dict,
        condition=condition,
        tags=['extracted_strings'],
    )


def generate_from_iocs(ioc_file, name, author='DFIR Claude Skill'):
    """Generate YARA rule from IOC extractor JSON output."""
    with open(ioc_file, 'r') as f:
        iocs = json.load(f)

    # Handle both list format and dict format
    if isinstance(iocs, dict):
        ioc_list = []
        for ioc_type, values in iocs.items():
            for v in values:
                ioc_list.append({'type': ioc_type, 'value': v})
        iocs = ioc_list

    meta = {
        'description': f'IOC-based rule with {len(iocs)} indicators',
        'author': author,
        'date': datetime.now().strftime('%Y-%m-%d'),
        'severity': 'high',
    }

    strings_dict = {}
    hash_conditions = []

    for i, ioc in enumerate(iocs):
        ioc_type = ioc.get('type', '')
        value = ioc.get('value', '')

        if ioc_type == 'md5':
            hash_conditions.append(f'hash.md5(0, filesize) == "{value.lower()}"')
        elif ioc_type == 'sha1':
            hash_conditions.append(f'hash.sha1(0, filesize) == "{value.lower()}"')
        elif ioc_type == 'sha256':
            hash_conditions.append(f'hash.sha256(0, filesize) == "{value.lower()}"')
        elif ioc_type in ('ipv4', 'domain', 'url'):
            strings_dict[f'$ioc_{i}'] = (value, 'nocase wide ascii')
        elif ioc_type == 'registry_path':
            strings_dict[f'$reg_{i}'] = (value, 'nocase wide ascii')

    modules = []
    condition = []

    if hash_conditions:
        modules.append('hash')
        if strings_dict:
            condition.append('(')
            condition.append('    ' + ' or\n        '.join(hash_conditions))
            condition.append(') or')
            condition.append(f'2 of ($ioc_*, $reg_*)')
        else:
            condition.append(' or\n        '.join(hash_conditions))
    elif strings_dict:
        threshold = max(1, len(strings_dict) // 3)
        condition.append(f'{threshold} of them')

    return build_yara_rule(
        name=name,
        meta=meta,
        strings_dict=strings_dict,
        condition=condition if condition else ['true'],
        modules=modules,
        tags=['ioc_based'],
    )


def analyze_rule(rule_file):
    """Analyze an existing YARA rule for quality and suggest improvements."""
    with open(rule_file, 'r') as f:
        rule_text = f.read()

    findings = {
        'file': rule_file,
        'issues': [],
        'warnings': [],
        'suggestions': [],
        'score': 100,
    }

    # Check for file type check
    if 'uint16(0)' not in rule_text and 'uint32(0)' not in rule_text:
        findings['issues'].append('No file magic byte check — rule will scan all file types (slow, FP-prone)')
        findings['score'] -= 15

    # Check for filesize limit
    if 'filesize' not in rule_text:
        findings['warnings'].append('No filesize limit — consider adding to improve performance')
        findings['score'] -= 10

    # Check for overly generic strings
    generic_patterns = ['cmd.exe', 'powershell', 'http://', 'https://', '.exe', '.dll']
    for gp in generic_patterns:
        if f'"{gp}"' in rule_text.lower() and rule_text.lower().count(f'"{gp}"') == 1:
            findings['warnings'].append(f'Single generic string "{gp}" may cause false positives')
            findings['score'] -= 5

    # Check for nocase usage
    string_count = rule_text.count(' = "')
    nocase_count = rule_text.count('nocase')
    if string_count > 0 and nocase_count < string_count // 2:
        findings['suggestions'].append('Consider adding "nocase" to more strings for better coverage')

    # Check for wide strings
    if 'wide' not in rule_text and ('Windows' in rule_text or 'PE' in rule_text):
        findings['suggestions'].append('PE files often have UTF-16 strings — consider adding "wide" modifier')

    # Check condition complexity
    condition_match = re.search(r'condition:\s*\n\s*(.*?)(?:\n\})', rule_text, re.DOTALL)
    if condition_match:
        cond = condition_match.group(1)
        if cond.strip() == 'any of them':
            findings['warnings'].append('"any of them" condition is very loose — consider requiring multiple strings')
            findings['score'] -= 10
        elif cond.strip() == 'all of them' and string_count <= 2:
            findings['suggestions'].append('With only 2 strings, "all of them" may be too specific')

    # Check metadata
    if 'meta:' not in rule_text:
        findings['issues'].append('No metadata section — add description, author, date, references')
        findings['score'] -= 10
    else:
        if 'description' not in rule_text:
            findings['warnings'].append('Missing description in metadata')
        if 'date' not in rule_text:
            findings['warnings'].append('Missing date in metadata')

    # Validate syntax if yara-python available
    try:
        import yara
        try:
            yara.compile(source=rule_text)
            findings['syntax_valid'] = True
        except yara.SyntaxError as e:
            findings['syntax_valid'] = False
            findings['issues'].append(f'Syntax error: {e}')
            findings['score'] -= 30
    except ImportError:
        findings['syntax_valid'] = 'not_checked (yara-python not installed)'

    findings['score'] = max(0, findings['score'])
    return findings


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='YARA Rule Generator')
    parser.add_argument('--mode', required=True,
                        choices=['behavioral', 'strings', 'ioc', 'pe-analysis', 'analyze'],
                        help='Generation mode')
    parser.add_argument('--name', default='generated_rule',
                        help='Rule name (alphanumeric + underscores)')
    parser.add_argument('--description', help='Behavioral description of malware')
    parser.add_argument('--strings-file', help='File with extracted strings (one per line)')
    parser.add_argument('--ioc-file', help='IOC JSON file (from ioc-extractor)')
    parser.add_argument('--rule-file', help='Existing YARA rule to analyze')
    parser.add_argument('--author', default='DFIR Claude Skill')
    parser.add_argument('--reference', default='', help='Reference URL')
    parser.add_argument('--severity', default='medium', choices=['low', 'medium', 'high', 'critical'])
    parser.add_argument('--mitre', default='', help='MITRE ATT&CK technique IDs')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')

    args = parser.parse_args()

    # Clean rule name
    name = re.sub(r'[^a-zA-Z0-9_]', '_', args.name)

    if args.mode == 'behavioral':
        if not args.description:
            print("Error: --description required for behavioral mode", file=sys.stderr)
            sys.exit(1)
        result = generate_from_behavioral(
            args.description, name, args.author, args.reference, args.severity, args.mitre
        )

    elif args.mode == 'strings':
        if not args.strings_file:
            print("Error: --strings-file required for strings mode", file=sys.stderr)
            sys.exit(1)
        result = generate_from_strings(args.strings_file, name, args.author)

    elif args.mode == 'ioc':
        if not args.ioc_file:
            print("Error: --ioc-file required for IOC mode", file=sys.stderr)
            sys.exit(1)
        result = generate_from_iocs(args.ioc_file, name, args.author)

    elif args.mode == 'analyze':
        if not args.rule_file:
            print("Error: --rule-file required for analyze mode", file=sys.stderr)
            sys.exit(1)
        analysis = analyze_rule(args.rule_file)
        result = json.dumps(analysis, indent=2)
        print(f"\n[*] Rule Quality Score: {analysis['score']}/100", file=sys.stderr)
        if analysis['issues']:
            print(f"[!] Issues: {len(analysis['issues'])}", file=sys.stderr)
        if analysis['warnings']:
            print(f"[!] Warnings: {len(analysis['warnings'])}", file=sys.stderr)

    else:
        print(f"Error: mode '{args.mode}' not yet implemented", file=sys.stderr)
        sys.exit(1)

    # Output
    if args.output:
        Path(args.output).write_text(result)
        print(f"[+] Rule written to {args.output}", file=sys.stderr)
    else:
        print(result)


if __name__ == '__main__':
    main()

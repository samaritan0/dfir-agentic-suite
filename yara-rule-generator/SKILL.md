---
name: yara-rule-generator
description: "Generate YARA rules from behavioral descriptions, malware samples, forensic findings, or threat intelligence reports. Produces well-structured YARA rules with metadata, string patterns, and conditions. Supports PE-specific features (imports, exports, sections, imphash), magic byte detection, and condition logic. Can also analyze existing YARA rules for quality, convert between YARA and Sigma where applicable, and generate rules from IOC lists. Use this skill whenever the user mentions YARA, detection rules, 'write a rule for', 'detect this malware', 'create a signature', 'generate YARA from', 'improve this YARA rule', or any request involving malware detection signatures. Also triggers when analyzing pefile output, strings output, or malware behavior reports that could be converted to detection rules."
---

# YARA Rule Generator

## What this skill does

Takes input from various sources and generates production-quality YARA rules:
1. **From behavioral descriptions**: "Detect a PE that drops files in Temp and contacts C2 via HTTPS"
2. **From malware samples** (via strings/pefile output): Extract unique strings, imports, sections
3. **From IOC lists**: Convert hashes, IPs, domains, file paths into YARA patterns
4. **From threat intel reports**: Parse TTP descriptions into detection logic
5. **Rule quality analysis**: Review existing rules for false-positive risk, performance, coverage

## Quick start

```bash
python3 /path/to/skills/yara-rule-generator/scripts/generate_yara.py \
    --mode behavioral \
    --description "Ransomware that encrypts files with .locked extension, drops ransom note README.txt, and contacts C2 via tor" \
    --name apt_ransomware_locked \
    --output rule.yar

python3 scripts/generate_yara.py \
    --mode strings \
    --strings-file extracted_strings.txt \
    --name trojan_backdoor_xyz \
    --output rule.yar

python3 scripts/generate_yara.py \
    --mode ioc \
    --ioc-file indicators.json \
    --name campaign_iocs_2024 \
    --output rule.yar

python3 scripts/generate_yara.py \
    --mode analyze \
    --rule-file existing_rule.yar
```

## Rule generation modes

### Mode: behavioral
Generate rules from natural language descriptions of malware behavior. The generator maps behavioral descriptions to YARA constructs:

| Behavior | YARA Construct |
|---|---|
| "drops files in Temp" | `$path = "\\Temp\\" nocase` |
| "contacts C2 via HTTPS" | `$url = /https?:\/\/[a-zA-Z0-9\.\-]+\// nocase` |
| "encrypts files" | PE import: `CryptEncrypt`, `BCryptEncrypt` |
| "creates service" | `$svc = "CreateServiceA" or import "advapi32.dll"` |
| "uses PowerShell" | `$ps = "powershell" nocase` + encoded variants |
| "packed/encrypted sections" | `math.entropy(section_offset, section_size) > 7.0` |
| "modifies registry Run key" | `$reg = "CurrentVersion\\Run" nocase` |

### Mode: strings
Takes output from `strings`, `FLOSS`, or manual string extraction and:
1. Filters noise (common strings, C runtime, Windows API)
2. Identifies unique/interesting strings (C2 URLs, mutex names, crypto constants, PDB paths)
3. Groups strings by category (network, filesystem, crypto, debug)
4. Generates rule with `any of ($network*)` style conditions

### Mode: ioc
Converts IOC lists (from ioc-extractor skill output) into YARA rules:
- File hashes → `hash.md5/sha1/sha256` conditions
- IP addresses → string patterns with network context
- Domains → string patterns with optional defanging
- File paths → string patterns with nocase
- Registry paths → string patterns

### Mode: pe-analysis
Takes pefile analysis output (JSON from pefile or PE-bear) and generates rules based on:
- Import hash (imphash)
- Specific API imports (suspicious combinations)
- Section names and entropy
- PE timestamp anomalies
- Resource characteristics
- Rich header hash
- Compilation artifacts (PDB path, compiler signatures)

### Mode: analyze
Reviews an existing YARA rule and reports:
- **False-positive risk**: Are strings too generic? Is the condition too loose?
- **Performance**: Are there expensive patterns (wide regex, large file scans)?
- **Coverage**: Could the rule be evaded by simple modifications?
- **Suggestions**: Specific improvements with reasoning

## Rule structure and best practices

Every generated rule follows this template:

```yara
rule <name> : <tags>
{
    meta:
        description = "..."
        author      = "DFIR Claude Skill"
        date        = "YYYY-MM-DD"
        reference   = "..."
        severity    = "critical|high|medium|low"
        tlp         = "WHITE|GREEN|AMBER|RED"
        mitre_attack = "T####"
        hash        = "..."  // if available

    strings:
        // Grouped by category with descriptive names
        $network_c2_1 = "..." nocase
        $filesystem_drop_1 = "..." nocase wide
        $crypto_const_1 = { DE AD BE EF }

    condition:
        // Layered conditions: file type + string combinations
        uint16(0) == 0x5A4D and  // PE check
        filesize < 5MB and
        (
            2 of ($network*) or
            (1 of ($crypto*) and 1 of ($filesystem*))
        )
}
```

### Key principles enforced by the generator:
- **Always include file type checks** (PE magic bytes, ELF, Mach-O, Office OLE)
- **Always include filesize limits** to prevent scanning huge files
- **Use `nocase` for strings** that could appear in different cases
- **Use `wide` for strings** that may be UTF-16 encoded (common in Windows)
- **Prefer hex patterns** for binary signatures (magic bytes, opcodes, crypto constants)
- **Group strings by purpose** with consistent naming ($category_detail_N)
- **Layered conditions**: file type AND (string combination OR import combination)
- **Include metadata**: date, author, description, MITRE ATT&CK, severity, reference

## Common YARA patterns library

The generator includes a reference library of common detection patterns. Read `references/common_patterns.md` for the full list. Key categories:

### Encryption indicators
- AES S-box constants: `{ 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }`
- RC4 init loop patterns
- RSA public key headers: `{ 30 82 01 22 30 0D 06 09 }`

### Process injection
- API sequence: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
- NtCreateSection + NtMapViewOfSection (syscall-based injection)

### Anti-analysis
- IsDebuggerPresent, CheckRemoteDebuggerPresent
- CPUID VM detection: `{ 0F A2 }` (CPUID instruction)
- Sleep-based evasion: GetTickCount/QueryPerformanceCounter checks

### Persistence
- Registry Run key paths
- Service creation APIs
- Scheduled task XML patterns
- WMI event subscription strings

## Integration with other skills

- **ioc-extractor**: IOC JSON output → `--mode ioc` for bulk rule generation
- **windows-artifact-triage**: Suspicious executables → `--mode pe-analysis` with pefile data
- **log-timeline-correlator**: Attack sequence patterns → `--mode behavioral` descriptions

## Script dependencies

```bash
pip install yara-python pefile --break-system-packages
```

yara-python is needed only for `--mode analyze` (rule validation). pefile is needed only for `--mode pe-analysis`. The generator works without both for behavioral, strings, and IOC modes.

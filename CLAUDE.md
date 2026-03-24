# DFIR Agentic Skills Suite for Claude Code

This project contains an **agentic DFIR orchestrator** and 4 forensic analysis skills. The orchestrator autonomously chains the skills with a reasoning loop, persistent case state, and human-in-the-loop checkpoints.

## Skills

### dfir-orchestrator (THE AGENTIC BRAIN)
Autonomous investigation engine that implements an OODA reasoning loop: Observe (scan evidence) → Orient (review findings) → Decide (pick next skill) → Act (execute) → Evaluate (parse results) → Checkpoint (human approval). Maintains persistent case state in `case_state.json`, supports investigation playbooks (ransomware, BEC, lateral movement), and generates comprehensive reports with IOC exports and MITRE ATT&CK mapping.

**Usage**: `python3 dfir-orchestrator/scripts/orchestrator.py --mode investigate --evidence-dir <path> --case-id INC-2024-001 --playbook ransomware`

### ioc-extractor
Extract and enrich IOCs (IPs, domains, hashes, URLs, CVEs, ATT&CK IDs, crypto addresses) from any text input. Enriches via VirusTotal, AbuseIPDB, Shodan, GreyNoise, OTX when API keys are set as env vars.

**Usage**: `python3 ioc-extractor/scripts/extract_iocs.py <file> --enrich --format markdown`

### windows-artifact-triage
Parse EZTools CSV output (PECmd, AmcacheParser, AppCompatCacheParser, EvtxECmd, MFTECmd), Chainsaw JSON, and Hayabusa CSV/JSONL. Auto-detects artifact types, cross-correlates execution evidence, finds persistence and lateral movement, detects timestomping and brute force.

**Usage**: `python3 windows-artifact-triage/scripts/triage_artifacts.py --input-dir <kape_output>`

### log-timeline-correlator
Merge and correlate timelines from Plaso l2tcsv, Hayabusa, Chainsaw, EvtxECmd, syslog, auth.log, and JSON logs (CloudTrail, Okta, Entra ID). Attack sequence detection with MITRE ATT&CK mapping, gap analysis, entity pivoting.

**Usage**: `python3 log-timeline-correlator/scripts/correlate_timeline.py --inputs file1.csv file2.json --attack-sequence`

### yara-rule-generator
Generate YARA rules from behavioral descriptions, extracted strings, IOC lists, or PE analysis. Includes rule quality analyzer and common detection pattern library.

**Usage**: `python3 yara-rule-generator/scripts/generate_yara.py --mode behavioral --description "ransomware that..." --name apt_rule`

## Usage

### Autonomous investigation (recommended)
The orchestrator handles the entire chain automatically:
```bash
python3 dfir-orchestrator/scripts/orchestrator.py \
    --mode investigate \
    --evidence-dir /cases/INC-2024-001/evidence/ \
    --case-id INC-2024-001 \
    --playbook ransomware
```

### Manual chaining (if you prefer step-by-step control)
The skills can also be used individually:
1. Run **windows-artifact-triage** on KAPE output → produces `extracted_hashes.txt` and `timeline.csv`
2. Feed hashes into **ioc-extractor** with `--enrich` → produces enriched IOC report
3. Feed `timeline.csv` into **log-timeline-correlator** with other log sources → unified correlated timeline
4. Use behavioral findings from steps 1-3 to generate detection rules via **yara-rule-generator**

## Dependencies

```bash
pip install pandas python-dateutil requests tldextract pefile yara-python stix2 --break-system-packages
```

Only `pandas` and `python-dateutil` are hard requirements. All other packages enable optional features (enrichment, STIX output, PE analysis, YARA validation) and degrade gracefully when missing.

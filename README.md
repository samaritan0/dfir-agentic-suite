# 🔍 DFIR Agentic Skills Suite

**An autonomous Digital Forensics & Incident Response toolkit built on Claude's skill and MCP ecosystem.**

5 forensic analysis skills, 4 MCP servers, 1 agentic orchestrator — designed to work with Claude Code, Claude Desktop, and Claude.ai. Entirely offline-capable for air-gapped forensic environments.

> ⚠️ **Work in Progress** — This project is under active development and has not been validated against real-world incident data at scale. Do not rely on it as your sole analysis tool for production incidents. Use it as a force multiplier alongside established DFIR workflows and always verify findings manually. Contributions and feedback are welcome.

---

## What is this?

A collection of **Claude skills** (structured instruction files + Python scripts) and **MCP servers** (Model Context Protocol integrations) that turn Claude into a DFIR co-analyst. The system can:

- **Extract and enrich IOCs** from any text — logs, alerts, emails, threat reports
- **Parse Windows forensic artifacts** — KAPE/EZTools CSV, Chainsaw, Hayabusa, event logs, MFT, prefetch, amcache, shimcache
- **Merge and correlate timelines** — from Plaso, Hayabusa, Chainsaw, syslog, CloudTrail, Okta, Entra ID
- **Generate YARA rules** — from behavioral descriptions, extracted strings, or IOC lists
- **Orchestrate full investigations autonomously** — with a reasoning loop, persistent case state, and human-in-the-loop checkpoints
- **Integrate with security tools via MCP** — SIEM queries, threat intel enrichment, case management, EDR response actions

The skills work **fully offline** by default. The MCP servers are optional add-ons that connect to external services when available.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude (any surface)                     │
│              Claude Code · Claude Desktop · Claude.ai           │
├────────────────────────┬────────────────────────────────────────┤
│                        │                                        │
│   MCP Servers          │   Local Skills (offline)               │
│   (optional, online)   │                                        │
│                        │   ┌──────────────────────────────┐     │
│   ┌─────────────┐      │   │  dfir-orchestrator           │     │
│   │ Threat Intel │      │  │  (autonomous reasoning loop) │     │
│   │ VT/Shodan/  │◄─────┤   └──────┬───────────────────────┘     │
│   │ AbuseIPDB   │      │          │                             │
│   └─────────────┘      │   ┌──────┴───────────────────────┐     │
│   ┌─────────────┐      │   │  ┌──────────┐ ┌───────────┐ │     │
│   │ SIEM        │      │   │  │ IOC      │ │ Windows   │ │     │
│   │ Splunk/     │◄─────┤   │  │ Extractor│ │ Artifact  │ │     │
│   │ Elastic/    │      │   │  └──────────┘ │ Triage    │ │     │
│   │ Wazuh       │      │   │  ┌──────────┐ └───────────┘ │     │
│   └─────────────┘      │   │  │ Timeline │ ┌───────────┐ │     │
│   ┌─────────────┐      │   │  │Correlator│ │ YARA      │ │     │
│   │ Case Mgmt   │      │   │  └──────────┘ │ Generator │ │     │
│   │ TheHive/    │◄─────┤   │               └───────────┘ │     │
│   │ IRIS        │      │   └─────────────────────────────┘     │
│   └─────────────┘      │                                        │
│   ┌─────────────┐      │                                        │
│   │ EDR Response│      │                                        │
│   │ CrowdStrike/│◄─────┘                                        │
│   │ Defender    │                                                │
│   └─────────────┘                                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Claude Code, Claude Desktop, or Claude.ai with skills support

### Install

```bash
git clone https://github.com/samaritan0/dfir-agentic-suite.git
cd dfir-agentic-suite

# Core dependencies (required)
pip install pandas python-dateutil --break-system-packages

# Optional: enrichment, STIX export, YARA validation
pip install requests tldextract stix2 yara-python pefile --break-system-packages

# Optional: MCP server support
pip install mcp --break-system-packages
```

### Run an autonomous investigation

```bash
python3 dfir-orchestrator/scripts/orchestrator.py \
    --mode investigate \
    --evidence-dir /path/to/kape-output/ \
    --case-id INC-2024-001 \
    --playbook ransomware
```

The orchestrator will:
1. Scan the evidence directory and identify artifact types
2. Run Windows artifact triage (prefetch, amcache, shimcache, event logs)
3. Enrich extracted hashes and IOCs against threat intel (if API keys configured)
4. Correlate timelines and detect attack sequences mapped to MITRE ATT&CK
5. Generate YARA detection rules from behavioral findings
6. Produce a comprehensive investigation report

It pauses at key checkpoints for human review. Use `--auto` to skip checkpoints for batch processing.

### Use individual skills

Each skill also works standalone:

```bash
# Extract IOCs from any file
python3 ioc-extractor/scripts/extract_iocs.py suspicious_email.txt --format markdown

# Parse KAPE/EZTools output
python3 windows-artifact-triage/scripts/triage_artifacts.py --input-dir ./kape_output/

# Correlate multiple timeline sources
python3 log-timeline-correlator/scripts/correlate_timeline.py \
    --inputs plaso.csv hayabusa.csv auth.log cloudtrail.json \
    --attack-sequence

# Generate a YARA rule from a behavioral description
python3 yara-rule-generator/scripts/generate_yara.py \
    --mode behavioral \
    --description "Ransomware that encrypts files, creates scheduled task, contacts C2 via tor" \
    --name apt_ransomware_tor \
    --severity critical
```

---

## Components

### Skills (offline, local analysis)

| Skill | What it does |
|---|---|
| **dfir-orchestrator** | 1,137 | Autonomous reasoning loop (OODA), case state management, human-in-the-loop, investigation playbooks |
| **windows-artifact-triage** | 961 | Parses EZTools CSV (PECmd, AmcacheParser, AppCompatCacheParser, EvtxECmd, MFTECmd), Chainsaw JSON, Hayabusa CSV/JSONL. Detects execution evidence, persistence, lateral movement, timestomping, brute force |
| **log-timeline-correlator** | 869 | Merges timelines from 8+ formats (Plaso l2tcsv, Hayabusa, Chainsaw, EvtxECmd, syslog, JSON logs). Attack sequence detection with ATT&CK mapping, gap analysis, entity pivoting |
| **ioc-extractor** | 669 | Extracts 14 IOC types (IPs, domains, hashes, URLs, CVEs, ATT&CK IDs, registry paths, crypto addresses, named pipes). Auto-refanging, deduplication, enrichment via threat intel APIs. Output: JSON/CSV/Markdown/STIX 2.1 |
| **yara-rule-generator** | 624 | Generates YARA rules from behavioral descriptions, extracted strings, or IOC lists. Includes rule quality analyzer and detection pattern reference library |

### MCP Servers (optional, external integrations)

| Server | Tools | Integrations |
|---|---|---|
| **dfir-threatintel** | 6 | VirusTotal, Shodan, AbuseIPDB, GreyNoise, AlienVault OTX — unified enrichment with aggregated verdict |
| **dfir-siem** | 3 | Splunk (SPL), Elastic (KQL), Wazuh — search, alert retrieval, notable events |
| **dfir-case-mgmt** | 8 | TheHive, IRIS DFIR — full CRUD for cases, alerts, tasks, observables, comments |
| **dfir-edr-response** | 6 | CrowdStrike Falcon, Microsoft Defender XDR — detections, host info, incidents + containment actions with mandatory human approval gate |

---

## Offline-First Design

The suite is built for forensic environments where network access is restricted or prohibited:

- **All 5 skills work completely offline** — they parse local files, correlate local data, and generate local output. No network calls required.
- **The orchestrator works offline** — it chains skills using local file I/O and maintains case state as a local JSON file.
- **MCP servers are entirely optional** — they enhance the workflow with real-time threat intel and platform integrations, but the core analysis pipeline doesn't depend on them.
- **IOC enrichment degrades gracefully** — if no API keys are configured, the extractor skips enrichment and produces the extraction report without reputation data.
- **No cloud dependencies** — no SaaS platform, no mandatory accounts, no telemetry. Everything runs locally.

This makes the suite suitable for air-gapped forensic workstations, classified environments, or situations where evidence handling policies prohibit external data transmission.

---

## MCP Configuration

### Claude Desktop

Copy the configuration file to the appropriate location:

```bash
# macOS
cp mcp-config/claude_desktop_config.json ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Windows
copy mcp-config\claude_desktop_config.json %APPDATA%\Claude\claude_desktop_config.json
```

Edit the file and replace `YOUR_*` placeholder values with your API keys. Remove servers you don't need. Restart Claude Desktop.

### Claude Code

```bash
cp mcp-config/claude_code_settings.json .claude/settings.json
```

Or merge the `mcpServers` key into your existing `.claude/settings.json`.

### API Keys

| Service | Env Variable | Free Tier | Required For |
|---|---|---|---|
| VirusTotal | `VT_API_KEY` | 4 req/min, 500/day | Hash/IP/domain reputation |
| Shodan | `SHODAN_API_KEY` | Limited | Open port/service enumeration |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1,000 checks/day | IP abuse reports |
| GreyNoise | `GREYNOISE_API_KEY` | 50 req/day | Internet noise classification |
| AlienVault OTX | `OTX_API_KEY` | Unlimited | Pulse-based threat intel |
| Splunk | `SPLUNK_TOKEN` | — | SIEM search and alerts |
| Elastic | `ELASTIC_API_KEY` | — | SIEM search and alerts |
| TheHive | `THEHIVE_API_KEY` | — | Case management |
| CrowdStrike | `CS_CLIENT_ID` + `CS_CLIENT_SECRET` | — | EDR detections and response |
| Defender | `DEFENDER_TENANT_ID` + `DEFENDER_CLIENT_ID` + `DEFENDER_CLIENT_SECRET` | — | EDR detections and response |

You only need the keys for the services you want to use. The system works with zero keys configured (offline mode).

---

## Investigation Playbooks

The orchestrator includes pre-built investigation playbooks:

| Playbook | Phases | Focus |
|---|---|---|
| `ransomware` | 6 | Execution evidence → IOC enrichment → timeline correlation → MFT deep-dive → YARA generation → report |
| `bec` | 4 | Email IOCs → cloud identity logs (Okta/Entra) → mail audit → report |
| `lateral_movement` | 5 | Host triage → entity pivot across logs → IOC enrichment → tool detection → report |
| `generic` | 2 | Auto-detect evidence → adaptive analysis |

```bash
python3 dfir-orchestrator/scripts/orchestrator.py \
    --mode investigate \
    --evidence-dir ./evidence/ \
    --case-id INC-2024-001 \
    --playbook ransomware
```

---

## Safety & Human-in-the-Loop

This suite is designed with forensic integrity in mind:

- **Read-only by default** — skills only read evidence files, they never modify them
- **Human checkpoints** — the orchestrator pauses for human review at critical findings, phase transitions, and every 5 iterations
- **EDR response actions are gated** — the `edr_contain_host` and similar tools require an explicit `human_approved=true` parameter; the server rejects the action without it
- **Stall detection** — the orchestrator stops if no new findings are produced after 3 consecutive iterations, preventing infinite loops
- **Full audit trail** — every action, decision, and human approval is logged in `case_state.json`

---

## Project Structure

```
dfir-agentic-suite/
├── README.md
├── CLAUDE.md                               # Claude Code project context
│
├── dfir-orchestrator/                      # The agentic brain
│   ├── SKILL.md                            # Skill instructions
│   ├── scripts/orchestrator.py             # Reasoning loop + decision engine
│   └── references/playbooks.json           # Investigation playbooks
│
├── ioc-extractor/                          # IOC extraction & enrichment
│   ├── SKILL.md
│   └── scripts/extract_iocs.py
│
├── windows-artifact-triage/                # Windows forensic artifact parser
│   ├── SKILL.md
│   └── scripts/triage_artifacts.py
│
├── log-timeline-correlator/                # Multi-source timeline correlation
│   ├── SKILL.md
│   └── scripts/correlate_timeline.py
│
├── yara-rule-generator/                    # YARA rule generation & analysis
│   ├── SKILL.md
│   ├── scripts/generate_yara.py
│   └── references/common_patterns.md
│
├── mcp-servers/                            # MCP server integrations
│   ├── dfir-threatintel/                   # VT, Shodan, AbuseIPDB, GreyNoise, OTX
│   ├── dfir-siem/                          # Splunk, Elastic, Wazuh
│   ├── dfir-case-mgmt/                     # TheHive, IRIS DFIR
│   └── dfir-edr-response/                  # CrowdStrike Falcon, Defender XDR
│
└── mcp-config/                             # Configuration templates
    ├── claude_desktop_config.json
    ├── claude_code_settings.json
    └── README.md
```

---

## Supported Artifact Formats

### Windows Artifacts (via EZTools / KAPE)

PECmd (Prefetch), AmcacheParser, AppCompatCacheParser (Shimcache), EvtxECmd (Event Logs with Maps), MFTECmd ($MFT and $J/USN Journal), SBECmd (ShellBags), LECmd (LNK), JLECmd (Jump Lists), RECmd (Registry)

### Detection Tool Output

Chainsaw (JSON), Hayabusa (CSV/JSONL), DeepBlueCLI (JSON)

### Log Formats

Plaso/log2timeline (l2tcsv, json_line), Syslog/auth.log, JSON logs (AWS CloudTrail, Okta System Log, Entra ID sign-in/audit logs, generic JSON)

### IOC Types

IPv4, IPv6, MD5, SHA1, SHA256, Domains, URLs, Email addresses, CVE IDs, MITRE ATT&CK technique IDs, Windows registry paths, Named pipes, Bitcoin addresses, Ethereum addresses, JARM fingerprints

---

## Roadmap

- [ ] Memory forensics integration (Volatility 3 MCP server)
- [ ] Cloud log parsers (native CloudTrail/Okta/Entra ID parsing with field-level analysis)
- [ ] Sigma rule generation alongside YARA
- [ ] MITRE ATT&CK Navigator layer export
- [ ] Evidence collection automation (KAPE command generation)
- [ ] Multi-host investigation correlation
- [ ] Integration tests with realistic forensic datasets
- [ ] Web UI dashboard for investigation progress
- [ ] Velociraptor VQL artifact generation

---

## Contributing

This is a work-in-progress project. Contributions are welcome — especially:

- **Testing against real forensic data** — the parsers have been validated against synthetic data but need broader testing
- **Additional artifact parsers** — macOS FSEvents/Unified Logs, Linux journal, browser forensics
- **MCP server improvements** — error handling, pagination, additional SIEM/EDR platforms
- **Playbook expansion** — new investigation playbooks for specific incident types
- **Documentation** — usage examples, video walkthroughs, integration guides

Please open an issue first to discuss significant changes.

---

## Disclaimer

This tool is provided for educational and research purposes. It is under active development and should not be used as the sole analysis tool for production incident response. Always verify AI-generated findings against source evidence. The authors are not responsible for decisions made based on this tool's output.

---

## License

GNU AGPLv3 (Affero General Public License)

---

## Acknowledgments

Built with [Claude](https://claude.ai) by Anthropic. Designed for the DFIR community.

Forensic tool references: [Eric Zimmerman's tools](https://ericzimmerman.github.io/), [Chainsaw](https://github.com/WithSecureLabs/chainsaw), [Hayabusa](https://github.com/Yamato-Security/hayabusa), [Volatility](https://github.com/volatilityfoundation/volatility3), [YARA](https://virustotal.github.io/yara/).

MCP ecosystem references: [Anthropic MCP](https://modelcontextprotocol.io/), community security MCP servers by [MHaggis](https://github.com/MHaggis/Security-Detections-MCP), [bornpresident](https://github.com/bornpresident/Volatility-MCP-Server), [THORCollective](https://github.com/THORCollective/threat-hunting-mcp-server).

# DFIR MCP Server Setup Guide

## Quick Start

### 1. Install dependencies
```bash
pip install mcp requests --break-system-packages
```

### 2. Pick your deployment target

#### Claude Desktop (macOS)
```bash
cp mcp-config/claude_desktop_config.json ~/Library/Application\ Support/Claude/claude_desktop_config.json
```
Then edit the file to add your API keys and restart Claude Desktop.

#### Claude Desktop (Windows)
```bash
copy mcp-config\claude_desktop_config.json %APPDATA%\Claude\claude_desktop_config.json
```

#### Claude Code
```bash
# From your project root:
cp mcp-config/claude_code_settings.json .claude/settings.json
# Or merge the mcpServers key into your existing .claude/settings.json
```

### 3. Configure API keys

Edit the config file and replace placeholder values with your actual keys.
You only need to configure the servers you plan to use — remove the others.

**Minimum viable setup** (just threat intel):
```json
{
    "mcpServers": {
        "dfir-threatintel": {
            "command": "python3",
            "args": ["-m", "dfir_threatintel_mcp"],
            "cwd": "/path/to/dfir-skills/mcp-servers/dfir-threatintel",
            "env": {
                "VT_API_KEY": "your-key-here"
            }
        }
    }
}
```

## Server Reference

### dfir-threatintel
**Tools**: `enrich_ip`, `enrich_hash`, `enrich_domain`, `shodan_host`, `bulk_enrich`, `check_available_services`

**API Keys** (at least one required):
| Variable | Service | Free Tier |
|---|---|---|
| `VT_API_KEY` | VirusTotal | 4 req/min, 500/day |
| `SHODAN_API_KEY` | Shodan | Limited (membership required for full API) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | 1000 checks/day |
| `GREYNOISE_API_KEY` | GreyNoise Community | 50 req/day |
| `OTX_API_KEY` | AlienVault OTX | Unlimited (free registration) |

### dfir-siem
**Tools**: `siem_search`, `siem_get_alerts`, `siem_check_status`

Set `SIEM_BACKEND` to `splunk`, `elastic`, or `wazuh`, then configure the matching variables:
- **Splunk**: `SPLUNK_HOST`, `SPLUNK_TOKEN`
- **Elastic**: `ELASTIC_HOST`, `ELASTIC_API_KEY`
- **Wazuh**: `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASSWORD`

### dfir-case-mgmt
**Tools**: `create_case`, `create_alert`, `add_observable`, `add_task`, `add_case_comment`, `get_case`, `list_cases`

Set `CASE_BACKEND` to `thehive` or `iris`:
- **TheHive**: `THEHIVE_URL`, `THEHIVE_API_KEY`
- **IRIS**: `IRIS_URL`, `IRIS_API_KEY`

### dfir-edr-response
**Tools**: 
- Read (safe): `edr_get_detections`, `edr_get_host`, `edr_get_incidents`, `edr_search_ioc`, `edr_advanced_query`
- Response (⚠️ requires `human_approved=true`): `edr_contain_host`, `edr_release_host`, `edr_run_scan`, `edr_collect_evidence`

Set `EDR_BACKEND` to `crowdstrike` or `defender`:
- **CrowdStrike**: `CS_CLIENT_ID`, `CS_CLIENT_SECRET`, `CS_BASE_URL`
- **Defender**: `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET`

**IMPORTANT**: All response actions are gated — the `human_approved` parameter must be explicitly set to `true` by the human operator. Claude should ALWAYS ask for confirmation before passing `human_approved=true`.

## Testing

Each server can be tested standalone:
```bash
# Check threat intel config
cd mcp-servers/dfir-threatintel
VT_API_KEY=your-key python3 -m dfir_threatintel_mcp --test

# Check SIEM config
cd mcp-servers/dfir-siem
SIEM_BACKEND=splunk SPLUNK_HOST=https://... SPLUNK_TOKEN=... python3 src/server.py
```

## Architecture

```
Claude (Desktop/Code/API)
    │
    ├── dfir-threatintel MCP ──→ VT, Shodan, AbuseIPDB, GreyNoise, OTX
    ├── dfir-siem MCP ──────────→ Splunk / Elastic / Wazuh
    ├── dfir-case-mgmt MCP ────→ TheHive / IRIS DFIR
    ├── dfir-edr-response MCP ─→ CrowdStrike Falcon / Microsoft Defender
    │
    └── dfir-orchestrator (skill)
        ├── windows-artifact-triage (skill)
        ├── ioc-extractor (skill)
        ├── log-timeline-correlator (skill)
        └── yara-rule-generator (skill)
```

MCP servers provide **real-time external integrations** (SIEM queries, threat intel enrichment, case management, EDR response).
Skills provide **local forensic analysis** (artifact parsing, timeline correlation, rule generation).
The orchestrator chains everything together with an autonomous reasoning loop.

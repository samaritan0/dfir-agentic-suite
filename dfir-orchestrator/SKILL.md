---
name: dfir-orchestrator
description: "Agentic DFIR orchestrator that autonomously investigates security incidents by chaining forensic skills (IOC extraction, Windows artifact triage, timeline correlation, YARA generation) with an autonomous reasoning loop, persistent case state, and human-in-the-loop approvals. Use this skill whenever the user mentions 'investigate', 'triage this incident', 'analyze this case', 'run a full investigation', 'what happened on this system', or asks for autonomous forensic analysis. Also triggers when multiple DFIR skills need to be chained together, when the user provides KAPE output or log files and wants comprehensive analysis, or when an alert needs end-to-end triage. This is the master orchestrator — it decides which sub-skills to invoke and in what order."
---

# DFIR Agentic Orchestrator

## What this skill does

This is the **brain** that turns the 4 passive DFIR skills into an autonomous investigation agent. It implements:

1. **Reasoning loop**: Observe → Orient → Decide → Act → Evaluate → Repeat (OODA-inspired)
2. **Skill routing**: Automatically selects which sub-skill to run based on available evidence and investigation state
3. **Persistent case state**: Tracks findings, IOCs, timeline events, and investigation progress across steps
4. **Human-in-the-loop**: Pauses for approval before destructive/irreversible actions and at key decision points
5. **Investigation playbooks**: Pre-defined investigation sequences for common incident types

## Architecture

```
                    ┌─────────────────────┐
                    │   Alert / User Ask  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   ORCHESTRATOR      │
                    │   (reasoning loop)  │◄────────────────┐
                    └──────────┬──────────┘                 │
                               │                            │
                    ┌──────────▼──────────┐                 │
                    │   DECIDE next step  │                 │
                    │   based on state    │                 │
                    └──────────┬──────────┘                 │
                               │                            │
              ┌────────┬───────┴───────┬────────┐           │
              ▼        ▼               ▼        ▼           │
         ┌────────┐┌────────┐   ┌──────────┐┌───────┐      │
         │Windows ││  IOC   │   │ Timeline ││ YARA  │      │
         │Triage  ││Extract │   │Correlator││ Gen   │      │
         └───┬────┘└───┬────┘   └────┬─────┘└──┬────┘      │
             │         │              │          │           │
             └─────────┴──────┬───────┴──────────┘           │
                              │                              │
                   ┌──────────▼──────────┐                   │
                   │  UPDATE CASE STATE  │                   │
                   │  Evaluate findings  ├───────────────────┘
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │ HUMAN CHECKPOINT?   │
                   │ Present findings    │
                   └─────────────────────┘
```

## How to use this skill

### Autonomous investigation from KAPE output
```bash
python3 scripts/orchestrator.py \
    --mode investigate \
    --evidence-dir /cases/INC-2024-001/kape_output/ \
    --case-id INC-2024-001 \
    --playbook ransomware \
    [--auto]  # skip human checkpoints (use for batch/automated runs)
```

### Triage a single alert
```bash
python3 scripts/orchestrator.py \
    --mode triage \
    --alert-file alert.json \
    --case-id ALERT-5678 \
    --evidence-dir /cases/ALERT-5678/
```

### Resume an existing investigation
```bash
python3 scripts/orchestrator.py \
    --mode resume \
    --case-dir /cases/INC-2024-001/
```

### Interactive investigation (Claude Code / Claude.ai)
When used through Claude directly (not CLI), the orchestrator works conversationally:
1. User provides evidence files or describes the incident
2. Orchestrator creates a case, initializes state
3. Runs first analysis pass (typically Windows triage or IOC extraction)
4. Presents findings and asks: "Based on these findings, I recommend [next step]. Proceed?"
5. On approval, continues the investigation loop
6. At each checkpoint, presents cumulative findings and recommended next actions

## The reasoning loop

Each iteration of the loop follows this sequence:

### 1. OBSERVE — What evidence do we have?
- Scan evidence directory for recognizable artifacts (KAPE output, logs, memory dumps, pcaps)
- Check case state for existing findings from previous iterations
- Identify what has already been analyzed and what's new

### 2. ORIENT — What does the evidence tell us?
- Review findings from the last skill execution
- Identify patterns: suspicious executables, persistence mechanisms, lateral movement indicators
- Score severity of findings (critical/high/medium/low/info)
- Identify gaps: "We found psexec execution but haven't checked for the corresponding network logon"

### 3. DECIDE — What should we do next?
The decision engine uses these priority rules:

**Priority 1 — Immediate triage** (first iteration):
- If KAPE/EZTools CSV available → run `windows-artifact-triage`
- If raw logs available → run `log-timeline-correlator`
- If text/alert data available → run `ioc-extractor`
- If memory dump available → flag for Volatility (MCP server needed)

**Priority 2 — Enrichment** (after initial triage):
- If hashes extracted → run `ioc-extractor --enrich` on extracted_hashes.txt
- If IPs/domains found → run `ioc-extractor --enrich` on findings
- If timeline gaps detected → search for additional log sources

**Priority 3 — Correlation** (after enrichment):
- If multiple timeline sources available → run `log-timeline-correlator --attack-sequence`
- If entity of interest identified → run with `--pivot-entity`
- Cross-reference execution evidence with network indicators

**Priority 4 — Detection generation** (after correlation):
- If behavioral pattern identified → run `yara-rule-generator --mode behavioral`
- If IOCs confirmed malicious → run `yara-rule-generator --mode ioc`
- If existing YARA rules available → run `--mode analyze` for quality check

**Priority 5 — Report generation** (investigation complete):
- Generate investigation summary from accumulated case state
- Produce ATT&CK navigator layer from detected techniques
- Create IOC export (STIX/CSV) for threat sharing
- Generate recommended remediation steps

### 4. ACT — Execute the chosen skill
- Run the selected sub-skill with appropriate parameters
- Capture stdout, stderr, and output files
- Log the action in the case state audit trail

### 5. EVALUATE — Did we learn something new?
- Parse skill output for new findings
- Compare against previous state: new IOCs? new timeline events? new detections?
- If no new findings → investigation may be complete (or we need different evidence)
- If critical findings → flag for human checkpoint
- Update the case state with new findings

### 6. CHECKPOINT — Should we pause for human review?
Pause for human approval when:
- Critical severity findings detected (confirmed malware, active C2, credential theft)
- Investigation is about to pivot to a new evidence source
- Remediation actions would be recommended (host isolation, password reset)
- Investigation loop has completed 5+ iterations without human review
- Any action that would modify evidence or systems (never happens in read-only forensics, but guard against it)

## Case state schema

The orchestrator maintains a JSON state file (`case_state.json`) that persists across iterations:

```json
{
    "case_id": "INC-2024-001",
    "created": "2024-06-15T10:30:00Z",
    "last_updated": "2024-06-15T11:45:00Z",
    "status": "in_progress",
    "playbook": "ransomware",
    "iteration": 5,

    "evidence_sources": [
        {"path": "/cases/INC-2024-001/kape_output/", "type": "kape", "analyzed": true},
        {"path": "/cases/INC-2024-001/okta_logs.json", "type": "json_log", "analyzed": false}
    ],

    "findings": {
        "severity_summary": {"critical": 2, "high": 5, "medium": 12, "low": 8},
        "execution_evidence": [...],
        "persistence_mechanisms": [...],
        "lateral_movement": [...],
        "iocs": {
            "ips": [{"value": "203.0.113.50", "enrichment": {...}, "context": "C2 callback"}],
            "hashes": [...],
            "domains": [...]
        },
        "timeline_events": [...],
        "attack_phases_detected": ["initial_access", "execution", "persistence", "lateral_movement"],
        "mitre_techniques": ["T1059.001", "T1543.003", "T1021.001"]
    },

    "investigation_log": [
        {"iteration": 1, "action": "windows-artifact-triage", "timestamp": "...", "summary": "..."},
        {"iteration": 2, "action": "ioc-extractor --enrich", "timestamp": "...", "summary": "..."},
        ...
    ],

    "pending_actions": [
        {"action": "correlate_okta_logs", "reason": "Lateral movement IPs match Okta source IPs", "priority": "high"}
    ],

    "human_decisions": [
        {"iteration": 3, "question": "Confirm C2 IP for blocklist?", "answer": "yes", "timestamp": "..."}
    ]
}
```

## Investigation playbooks

Pre-defined sequences in `references/playbooks.json` for common incident types. The orchestrator follows the playbook but adapts based on what the evidence reveals.

### Ransomware playbook
1. Windows artifact triage → evidence of execution, persistence
2. IOC enrichment → hash reputation, C2 IP analysis
3. Timeline correlation → attack sequence reconstruction
4. MFT analysis → identify encrypted file patterns, ransom note timestamps
5. YARA generation → behavioral rule for the ransomware variant
6. Report → executive summary + technical timeline + IOC list + remediation steps

### Business Email Compromise playbook
1. IOC extraction from email headers/body
2. Cloud identity log analysis (Okta/Entra ID sign-in logs)
3. Mail access audit (MailItemsAccessed, inbox rule creation)
4. Timeline correlation → session reconstruction
5. Report → compromised accounts, accessed data, forwarding rules

### Lateral movement playbook
1. Windows artifact triage → focus on lateral movement indicators
2. Event log analysis → 4624 Type 3/10, service installs, PsExec
3. Entity pivoting → trace each compromised account across systems
4. Timeline correlation → map the movement path
5. YARA generation → rules for tools used (psexec, mimikatz, etc.)

## Integration with MCP servers

When MCP servers are available, the orchestrator can be event-driven:

| MCP Server | Trigger | Orchestrator Action |
|---|---|---|
| Splunk/Elastic/Wazuh | Critical alert | Auto-create case, run triage playbook |
| VirusTotal | Hash submission result | Update IOC enrichment in case state |
| TheHive/IRIS | New case created | Initialize investigation, pull case artifacts |
| CrowdStrike Falcon | Detection | Extract IOCs, correlate with existing cases |
| Microsoft Sentinel | Incident | Pull KQL results, correlate with Entra logs |

The MCP integration is additive — the orchestrator works fully offline with local evidence files. MCP servers enhance it with real-time data and automated triggers.

## Script dependencies

```bash
pip install pandas python-dateutil requests --break-system-packages
```

Same dependencies as the sub-skills. The orchestrator itself is pure Python stdlib + the sub-skill scripts.

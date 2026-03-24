---
name: log-timeline-correlator
description: "Parse, normalize, and correlate forensic timelines from Plaso/log2timeline (l2tcsv, json_line), Hayabusa (CSV/JSONL), Chainsaw (JSON), and raw log files (syslog, auth.log, JSON-formatted logs, Windows XML event logs). Produces unified UTC timelines, detects attack sequences, and maps findings to MITRE ATT&CK. Use this skill whenever the user mentions timeline, plaso, log2timeline, supertimeline, l2tcsv, timeline correlation, log parsing, attack sequence, 'merge these logs', 'correlate events across sources', 'build a timeline', 'what happened between', or 'reconstruct the attack'. Also triggers for temporal analysis, time-window queries, and gap detection in forensic timelines."
---

# Log Analyzer & Timeline Correlator

## What this skill does

Takes forensic timeline output from multiple tools and raw log files, then:
1. **Normalizes** all timestamps to UTC with microsecond precision
2. **Merges** events from different sources into a single sorted timeline
3. **Correlates** related events within configurable time windows
4. **Detects** attack sequences (recon → access → execution → persistence → exfil patterns)
5. **Maps** detected patterns to MITRE ATT&CK techniques
6. **Identifies** gaps where evidence may be missing or tampered with
7. Outputs unified timeline (CSV/JSON) plus an analysis report (Markdown)

## Supported input formats

| Format | Source Tool | Key Fields |
|---|---|---|
| **l2tcsv** | Plaso/log2timeline | date, time, timezone, MACB, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra |
| **json_line** (JSONL) | Plaso --output-format json_line | datetime, timestamp_desc, source_short, source_long, message, filename, display_name |
| **Hayabusa CSV** | Hayabusa csv-timeline | Timestamp, RuleTitle, Level, Computer, Channel, EventID, Details, MitreAttack |
| **Hayabusa JSONL** | Hayabusa json-timeline | Same fields as CSV in JSON objects |
| **Chainsaw JSON** | Chainsaw | name, level, timestamp, sigma, document, tags |
| **Syslog** | Linux syslog/rsyslog | Standard syslog format with facility.severity |
| **auth.log** | Linux PAM/sshd | Timestamp + auth messages |
| **JSON logs** | AWS CloudTrail, Okta, Entra ID, generic | Auto-detected timestamp fields |
| **EVTX CSV** | EvtxECmd | TimeCreated, EventId, Channel, PayloadData* |

## Quick start

```bash
python3 /path/to/skills/log-timeline-correlator/scripts/correlate_timeline.py \
    --inputs plaso_output.csv hayabusa_timeline.csv auth.log cloudtrail.json \
    --output-dir ./correlated/ \
    [--timerange "2024-06-15T00:00:00Z,2024-06-16T23:59:59Z"] \
    [--window 300] \
    [--pivot-entity "10.0.0.50"] \
    [--attack-sequence] \
    [--format csv|json|markdown]
```

## Core analysis capabilities

### Temporal correlation
Events from different sources that occur within a configurable window (default: 300 seconds) around a pivot event are grouped into "correlation clusters." This reveals attack chains that span multiple log sources — for example, a CloudTrail `ConsoleLogin` followed by a Hayabusa detection of `Suspicious PowerShell` on the same user within 5 minutes.

### Attack sequence detection
When `--attack-sequence` is enabled, the correlator looks for canonical attack progression patterns:

1. **Reconnaissance**: port scans, directory enumeration, failed auth clusters
2. **Initial Access**: successful auth after failed attempts, unusual logon source
3. **Execution**: process creation, script execution, scheduled task creation
4. **Persistence**: registry modification, service install, account creation
5. **Lateral Movement**: RDP (Type 10), network logon (Type 3), PsExec
6. **Collection/Staging**: archive creation, file copy to staging directory
7. **Exfiltration**: large outbound transfers, cloud storage access, DNS tunneling indicators

Each detected phase is tagged with the corresponding MITRE ATT&CK tactic and technique IDs.

### Gap analysis
The correlator identifies suspicious gaps in log coverage:
- Time periods with zero events between otherwise active periods
- Sudden disappearance of a log source (e.g., Sysmon stops logging)
- Event log clearing events (Event 1102, Event 104)
- Timestamp discontinuities suggesting log tampering

### Entity pivoting
Use `--pivot-entity` to focus analysis on a specific IP, hostname, username, or hash. The correlator extracts all events involving that entity across all log sources and builds an entity-centric timeline.

## Integration with other skills

- **windows-artifact-triage**: The `timeline.csv` output from that skill is a native input format here
- **ioc-extractor**: Run IOC extraction on the merged timeline to find indicators across all log sources
- **yara-rule-generator**: Behavioral patterns from attack sequence detection can seed YARA rule creation

## Output files

| File | Contents |
|---|---|
| `merged_timeline.csv` | All events sorted by UTC timestamp |
| `correlation_clusters.json` | Groups of related events within time windows |
| `attack_sequence.json` | Detected attack phases with ATT&CK mapping |
| `gap_analysis.json` | Suspicious log gaps and discontinuities |
| `entity_timeline.csv` | Events for pivoted entity (if `--pivot-entity` used) |
| `analysis_report.md` | Human-readable summary of all findings |

## Script dependencies

```bash
pip install python-dateutil --break-system-packages
```

python-dateutil handles the wide variety of timestamp formats found across forensic tools and log sources. The script falls back to manual parsing if dateutil is unavailable.

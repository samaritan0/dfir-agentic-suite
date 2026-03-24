#!/usr/bin/env python3
"""
DFIR Agentic Orchestrator
Autonomous investigation engine that chains DFIR skills with a reasoning loop,
persistent case state, and human-in-the-loop checkpoints.

Part of the DFIR Skills Suite for Claude.
"""

import argparse
import json
import os
import subprocess
import sys
import shutil
import glob
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
from enum import Enum
from typing import Optional

# ─── Constants ───────────────────────────────────────────────────────────────

SKILLS_DIR = Path(__file__).parent.parent  # dfir-skills root
MAX_ITERATIONS = 15
CHECKPOINT_INTERVAL = 5  # Force human checkpoint every N iterations

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

class InvestigationStatus(Enum):
    INITIALIZED = "initialized"
    IN_PROGRESS = "in_progress"
    AWAITING_HUMAN = "awaiting_human"
    COMPLETED = "completed"
    STALLED = "stalled"  # No new findings after 3 iterations


# ─── Case State Manager ─────────────────────────────────────────────────────

class CaseState:
    """Persistent investigation state that survives across orchestrator runs."""

    def __init__(self, case_dir: Path, case_id: str):
        self.case_dir = case_dir
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = case_dir / "case_state.json"
        self.case_id = case_id

        if self.state_file.exists():
            self.state = json.loads(self.state_file.read_text())
            self._log(f"Resumed case {case_id} at iteration {self.state['iteration']}")
        else:
            self.state = self._init_state()
            self._log(f"Created new case {case_id}")
            self.save()

    def _init_state(self) -> dict:
        return {
            "case_id": self.case_id,
            "created": self._now(),
            "last_updated": self._now(),
            "status": InvestigationStatus.INITIALIZED.value,
            "playbook": None,
            "iteration": 0,
            "evidence_sources": [],
            "findings": {
                "severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "execution_evidence": [],
                "persistence_mechanisms": [],
                "lateral_movement": [],
                "iocs": {"ips": [], "hashes": [], "domains": [], "urls": [], "emails": [], "cves": []},
                "timeline_events_count": 0,
                "attack_phases_detected": [],
                "mitre_techniques": [],
                "yara_rules_generated": [],
                "timestomped_files": [],
                "bruteforce_detections": [],
            },
            "investigation_log": [],
            "pending_actions": [],
            "human_decisions": [],
            "skills_executed": [],
            "stall_counter": 0,  # Tracks iterations with no new findings
        }

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _log(self, message: str):
        print(f"[{self._now()}] [{self.case_id}] {message}", file=sys.stderr)

    def save(self):
        self.state["last_updated"] = self._now()
        self.state_file.write_text(json.dumps(self.state, indent=2, default=str))

    def add_evidence(self, path: str, evidence_type: str, analyzed: bool = False):
        entry = {"path": path, "type": evidence_type, "analyzed": analyzed, "added": self._now()}
        if not any(e["path"] == path for e in self.state["evidence_sources"]):
            self.state["evidence_sources"].append(entry)
            self.save()

    def mark_evidence_analyzed(self, path: str):
        for e in self.state["evidence_sources"]:
            if e["path"] == path:
                e["analyzed"] = True
        self.save()

    def log_action(self, skill: str, params: str, summary: str, output_files: list = None):
        self.state["iteration"] += 1
        self.state["investigation_log"].append({
            "iteration": self.state["iteration"],
            "skill": skill,
            "params": params,
            "timestamp": self._now(),
            "summary": summary,
            "output_files": output_files or [],
        })
        if skill not in self.state["skills_executed"]:
            self.state["skills_executed"].append(skill)
        self.state["status"] = InvestigationStatus.IN_PROGRESS.value
        self.save()

    def add_findings(self, category: str, findings: list):
        """Add findings and return count of genuinely new items."""
        existing = self.state["findings"].get(category, [])
        if isinstance(existing, int):
            # For timeline_events_count
            old_count = existing
            self.state["findings"][category] = findings if isinstance(findings, int) else len(findings)
            return self.state["findings"][category] - old_count

        new_count = 0
        existing_values = set()
        for e in existing:
            if isinstance(e, dict):
                existing_values.add(json.dumps(e, sort_keys=True, default=str))
            else:
                existing_values.add(str(e))

        for f in findings:
            key = json.dumps(f, sort_keys=True, default=str) if isinstance(f, dict) else str(f)
            if key not in existing_values:
                existing.append(f)
                existing_values.add(key)
                new_count += 1

        self.state["findings"][category] = existing
        self.save()
        return new_count

    def add_iocs(self, ioc_type: str, values: list):
        """Add IOCs and return count of new ones."""
        existing = set()
        for ioc in self.state["findings"]["iocs"].get(ioc_type, []):
            v = ioc["value"] if isinstance(ioc, dict) else ioc
            existing.add(v)

        new_count = 0
        for v in values:
            val = v["value"] if isinstance(v, dict) else v
            if val not in existing:
                self.state["findings"]["iocs"][ioc_type].append(v if isinstance(v, dict) else {"value": val})
                existing.add(val)
                new_count += 1

        self.save()
        return new_count

    def add_mitre_techniques(self, techniques: list):
        existing = set(self.state["findings"]["mitre_techniques"])
        new = [t for t in techniques if t not in existing]
        self.state["findings"]["mitre_techniques"].extend(new)
        self.save()
        return len(new)

    def add_attack_phases(self, phases: list):
        existing = set(self.state["findings"]["attack_phases_detected"])
        new = [p for p in phases if p not in existing]
        self.state["findings"]["attack_phases_detected"].extend(new)
        self.save()
        return len(new)

    def update_severity(self, severity: str, count: int):
        self.state["findings"]["severity_summary"][severity] = \
            self.state["findings"]["severity_summary"].get(severity, 0) + count
        self.save()

    def record_human_decision(self, question: str, answer: str):
        self.state["human_decisions"].append({
            "iteration": self.state["iteration"],
            "question": question,
            "answer": answer,
            "timestamp": self._now(),
        })
        self.save()

    def set_pending_action(self, action: str, reason: str, priority: str = "medium"):
        self.state["pending_actions"].append({
            "action": action, "reason": reason, "priority": priority, "added": self._now()
        })
        self.save()

    def clear_pending_action(self, action: str):
        self.state["pending_actions"] = [
            a for a in self.state["pending_actions"] if a["action"] != action
        ]
        self.save()

    def get_unanalyzed_evidence(self) -> list:
        return [e for e in self.state["evidence_sources"] if not e["analyzed"]]

    def get_total_findings_count(self) -> int:
        f = self.state["findings"]
        total = 0
        for key, val in f.items():
            if isinstance(val, list):
                total += len(val)
            elif isinstance(val, int):
                total += val
            elif isinstance(val, dict) and key == "iocs":
                total += sum(len(v) for v in val.values())
            elif isinstance(val, dict) and key == "severity_summary":
                total += sum(val.values())
        return total


# ─── Evidence Scanner ────────────────────────────────────────────────────────

EVIDENCE_PATTERNS = {
    "kape_output": ["**/Module_Output/**", "**/EvtxECmd*", "**/PECmd*", "**/AmcacheParser*"],
    "evtx_csv": ["**/*evtx*.csv", "**/*EvtxECmd*.csv"],
    "prefetch_csv": ["**/*prefetch*.csv", "**/*PECmd*.csv"],
    "amcache_csv": ["**/*amcache*.csv", "**/*Amcache*.csv"],
    "shimcache_csv": ["**/*shimcache*.csv", "**/*AppCompat*.csv"],
    "mft_csv": ["**/*MFT*.csv"],
    "usn_csv": ["**/*USN*.csv", "**/*$J*.csv"],
    "hayabusa": ["**/*hayabusa*.csv", "**/*hayabusa*.jsonl"],
    "chainsaw": ["**/*chainsaw*.json"],
    "plaso": ["**/*plaso*.csv", "**/*l2t*.csv", "**/*supertimeline*.csv"],
    "syslog": ["**/auth.log*", "**/syslog*", "**/messages*", "**/secure*"],
    "json_log": ["**/*cloudtrail*.json", "**/*okta*.json", "**/*entra*.json",
                  "**/*signin*.json", "**/*audit*.json"],
    "memory_dump": ["**/*.raw", "**/*.mem", "**/*.vmem", "**/*.dmp"],
    "pcap": ["**/*.pcap", "**/*.pcapng"],
    "yara_rule": ["**/*.yar", "**/*.yara"],
}


def scan_evidence(evidence_dir: Path) -> dict:
    """Scan a directory for recognizable forensic evidence files."""
    found = defaultdict(list)

    for evidence_type, patterns in EVIDENCE_PATTERNS.items():
        for pattern in patterns:
            for match in evidence_dir.glob(pattern):
                if match.is_file() and match.stat().st_size > 0:
                    found[evidence_type].append(str(match))

    # Dedup
    for k in found:
        found[k] = sorted(set(found[k]))

    return dict(found)


# ─── Skill Executor ──────────────────────────────────────────────────────────

def find_script(skill_name: str) -> Optional[Path]:
    """Find a skill's script relative to the orchestrator."""
    candidates = [
        SKILLS_DIR / skill_name / "scripts",
        SKILLS_DIR.parent / skill_name / "scripts",
        Path(f"/mnt/skills/user/{skill_name}/scripts"),
    ]
    script_map = {
        "ioc-extractor": "extract_iocs.py",
        "windows-artifact-triage": "triage_artifacts.py",
        "log-timeline-correlator": "correlate_timeline.py",
        "yara-rule-generator": "generate_yara.py",
    }
    script_name = script_map.get(skill_name, "")
    for base in candidates:
        script = base / script_name
        if script.exists():
            return script
    return None


def run_skill(skill_name: str, args: list, output_dir: Path, case: CaseState) -> dict:
    """Execute a sub-skill and capture results."""
    script = find_script(skill_name)
    if not script:
        return {"success": False, "error": f"Script not found for {skill_name}"}

    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(script)] + args

    case._log(f"Executing: {skill_name} {' '.join(args)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            cwd=str(SKILLS_DIR),
        )

        output_files = list(output_dir.glob("*")) if output_dir.exists() else []

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "output_files": [str(f) for f in output_files],
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"{skill_name} timed out after 600s"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ─── Result Parsers ──────────────────────────────────────────────────────────

def parse_triage_results(output_dir: Path, case: CaseState) -> dict:
    """Parse windows-artifact-triage output and update case state."""
    new_findings = {}

    # Execution evidence
    exec_file = output_dir / "execution_evidence.json"
    if exec_file.exists():
        data = json.loads(exec_file.read_text())
        suspicious = [e for e in data if e.get("suspicious")]
        new_count = case.add_findings("execution_evidence", suspicious)
        new_findings["suspicious_executables"] = new_count
        case.update_severity("high", len([e for e in suspicious if "known_tool" in e.get("reasons", [])]))

        # Extract hashes for IOC enrichment
        hashes = []
        for e in data:
            for h in e.get("hashes", []):
                hashes.append({"value": h, "context": f"amcache:{e.get('executable', '')}"})
        if hashes:
            case.add_iocs("hashes", hashes)

    # Persistence
    persist_file = output_dir / "persistence_mechanisms.json"
    if persist_file.exists():
        data = json.loads(persist_file.read_text())
        suspicious = [p for p in data if p.get("suspicious")]
        new_count = case.add_findings("persistence_mechanisms", suspicious)
        new_findings["persistence_mechanisms"] = new_count
        if suspicious:
            case.update_severity("high", len(suspicious))

    # Lateral movement
    lateral_file = output_dir / "lateral_movement.json"
    if lateral_file.exists():
        data = json.loads(lateral_file.read_text())
        summary = data.get("summary", {})
        new_findings["lateral_movement_summary"] = summary
        if summary.get("psexec_indicators", 0) > 0:
            case.update_severity("critical", 1)

        # Extract source IPs
        for session in data.get("rdp_sessions", []) + data.get("network_logons", []):
            ip = session.get("source_ip", "")
            if ip and ip not in ("", "-", "::1", "127.0.0.1"):
                case.add_iocs("ips", [{"value": ip, "context": "lateral_movement"}])

    # Brute force
    bf_file = output_dir / "bruteforce_detection.json"
    if bf_file.exists():
        data = json.loads(bf_file.read_text())
        if data:
            case.add_findings("bruteforce_detections", data)
            new_findings["bruteforce_attacks"] = len(data)
            case.update_severity("high", len(data))

    # Timestomping
    ts_file = output_dir / "timestomping.json"
    if ts_file.exists():
        data = json.loads(ts_file.read_text())
        if data:
            case.add_findings("timestomped_files", data[:20])  # Cap at 20
            new_findings["timestomped_files"] = len(data)
            case.update_severity("high", min(len(data), 5))

    # Extracted hashes file
    hash_file = output_dir / "extracted_hashes.txt"
    if hash_file.exists():
        hashes = [h.strip() for h in hash_file.read_text().splitlines() if h.strip()]
        new_findings["extracted_hashes_count"] = len(hashes)

    return new_findings


def parse_ioc_results(output_file: Path, case: CaseState) -> dict:
    """Parse ioc-extractor output and update case state."""
    new_findings = {}
    if not output_file.exists():
        return new_findings

    data = json.loads(output_file.read_text())
    ioc_list = data if isinstance(data, list) else []

    type_map = {
        "ipv4": "ips", "ipv6": "ips",
        "md5": "hashes", "sha1": "hashes", "sha256": "hashes",
        "domain": "domains", "url": "urls",
        "email": "emails", "cve": "cves",
    }

    for ioc in ioc_list:
        ioc_type = ioc.get("type", "")
        case_type = type_map.get(ioc_type)
        if case_type:
            new = case.add_iocs(case_type, [ioc])
            new_findings[f"new_{case_type}"] = new_findings.get(f"new_{case_type}", 0) + new

        # Flag malicious enrichment results
        vt = ioc.get("enrichment", {}).get("virustotal", {})
        if vt.get("malicious", 0) > 5:
            case.update_severity("critical", 1)
        elif vt.get("malicious", 0) > 0:
            case.update_severity("high", 1)

    # MITRE ATT&CK from IOCs
    mitre_iocs = [i["value"] for i in ioc_list if i.get("type") == "mitre_attack"]
    if mitre_iocs:
        case.add_mitre_techniques(mitre_iocs)

    return new_findings


def parse_timeline_results(output_dir: Path, case: CaseState) -> dict:
    """Parse log-timeline-correlator output and update case state."""
    new_findings = {}

    # Attack sequence
    seq_file = output_dir / "attack_sequence.json"
    if seq_file.exists():
        data = json.loads(seq_file.read_text())
        phases = [p["phase"] for p in data.get("sequence", [])]
        new = case.add_attack_phases(phases)
        new_findings["new_attack_phases"] = new
        new_findings["total_phases_detected"] = data.get("phases_detected", 0)
        new_findings["attack_progression_complete"] = data.get("attack_progression_complete", False)

        # Extract MITRE techniques
        for phase in data.get("sequence", []):
            case.add_mitre_techniques(phase.get("mitre_tactic", []))

        if data.get("attack_progression_complete"):
            case.update_severity("critical", 1)

    # Gap analysis
    gap_file = output_dir / "gap_analysis.json"
    if gap_file.exists():
        data = json.loads(gap_file.read_text())
        suspicious_gaps = [g for g in data if g.get("suspicious")]
        new_findings["suspicious_gaps"] = len(suspicious_gaps)
        log_clearing = [g for g in data if g.get("type") == "log_clearing"]
        if log_clearing:
            new_findings["log_clearing_events"] = len(log_clearing)
            case.update_severity("critical", len(log_clearing))

    # Timeline size
    timeline_file = output_dir / "merged_timeline.csv"
    if timeline_file.exists():
        line_count = sum(1 for _ in open(timeline_file)) - 1  # minus header
        case.add_findings("timeline_events_count", line_count)
        new_findings["timeline_events"] = line_count

    return new_findings


# ─── Decision Engine ─────────────────────────────────────────────────────────

class Decision:
    """Represents a decision about what to do next."""
    def __init__(self, skill: str, args: list, reason: str,
                 priority: int = 5, checkpoint: bool = False,
                 checkpoint_reason: str = ""):
        self.skill = skill
        self.args = args
        self.reason = reason
        self.priority = priority
        self.checkpoint = checkpoint
        self.checkpoint_reason = checkpoint_reason

    def __repr__(self):
        return f"Decision(skill={self.skill}, priority={self.priority}, reason={self.reason})"


def decide_next_action(case: CaseState, evidence: dict, iteration_output_dir: Path) -> Optional[Decision]:
    """The reasoning engine. Decides what skill to run next based on case state."""

    findings = case.state["findings"]
    executed = case.state["skills_executed"]
    iteration = case.state["iteration"]
    unanalyzed = case.get_unanalyzed_evidence()

    output_base = str(iteration_output_dir)

    # ──── Priority 1: Initial triage (first iterations) ────
    if "windows-artifact-triage" not in executed:
        # Check for Windows artifacts
        win_evidence = []
        for et in ["kape_output", "evtx_csv", "prefetch_csv", "amcache_csv", "shimcache_csv"]:
            win_evidence.extend(evidence.get(et, []))
        if win_evidence:
            # Build args for triage
            args = ["--output-dir", output_base + "/triage"]
            # Try input-dir if kape output detected
            if evidence.get("kape_output"):
                kape_dir = str(Path(evidence["kape_output"][0]).parent.parent)
                args += ["--input-dir", kape_dir]
            else:
                if evidence.get("evtx_csv"):
                    args += ["--evtx"] + evidence["evtx_csv"][:5]
                if evidence.get("prefetch_csv"):
                    args += ["--prefetch", evidence["prefetch_csv"][0]]
                if evidence.get("amcache_csv"):
                    args += ["--amcache", evidence["amcache_csv"][0]]
                if evidence.get("shimcache_csv"):
                    args += ["--shimcache", evidence["shimcache_csv"][0]]

            return Decision(
                skill="windows-artifact-triage",
                args=args,
                reason="Windows forensic artifacts detected — running initial triage",
                priority=1,
            )

    # Check for log files that haven't been processed
    log_evidence = []
    for et in ["syslog", "json_log", "plaso"]:
        log_evidence.extend(evidence.get(et, []))
    if log_evidence and "log-timeline-correlator" not in executed and "windows-artifact-triage" not in executed:
        args = ["--inputs"] + log_evidence[:10] + ["--output-dir", output_base + "/timeline", "--attack-sequence"]
        return Decision(
            skill="log-timeline-correlator",
            args=args,
            reason="Log files detected — running initial timeline analysis",
            priority=1,
        )

    # ──── Priority 2: IOC enrichment ────
    if "windows-artifact-triage" in executed and "ioc-extractor" not in executed:
        # Find extracted hashes or triage summary to enrich
        hash_files = list(Path(case.case_dir).rglob("extracted_hashes.txt"))
        summary_files = list(Path(case.case_dir).rglob("triage_summary.md"))

        input_file = None
        if hash_files:
            input_file = str(hash_files[0])
        elif summary_files:
            input_file = str(summary_files[0])

        if input_file:
            output_file = output_base + "/iocs/enriched_iocs.json"
            Path(output_base + "/iocs").mkdir(parents=True, exist_ok=True)
            args = [input_file, "--enrich", "--format", "json", "-o", output_file]
            return Decision(
                skill="ioc-extractor",
                args=args,
                reason="Extracted hashes/indicators available — enriching against threat intel",
                priority=2,
            )

    # ──── Priority 3: Timeline correlation ────
    if "windows-artifact-triage" in executed and "log-timeline-correlator" not in executed:
        timeline_files = list(Path(case.case_dir).rglob("timeline.csv"))
        additional = []
        for et in ["plaso", "syslog", "json_log", "hayabusa"]:
            additional.extend(evidence.get(et, []))

        all_inputs = [str(f) for f in timeline_files] + additional
        if all_inputs:
            args = ["--inputs"] + all_inputs[:10]
            args += ["--output-dir", output_base + "/correlated", "--attack-sequence"]

            # Entity pivot if we have IPs from lateral movement
            ips = findings.get("iocs", {}).get("ips", [])
            lateral_ips = [ip for ip in ips if isinstance(ip, dict) and ip.get("context") == "lateral_movement"]
            if lateral_ips:
                args += ["--pivot-entity", lateral_ips[0]["value"]]

            return Decision(
                skill="log-timeline-correlator",
                args=args,
                reason="Multiple timeline sources available — correlating and detecting attack sequence",
                priority=3,
                checkpoint=True,
                checkpoint_reason="Attack sequence analysis complete — review findings before detection generation",
            )

    # ──── Priority 4: YARA rule generation ────
    if ("windows-artifact-triage" in executed or "ioc-extractor" in executed) and \
       "yara-rule-generator" not in executed:

        # Build behavioral description from findings
        phases = findings.get("attack_phases_detected", [])
        persistence = findings.get("persistence_mechanisms", [])
        exec_evidence = findings.get("execution_evidence", [])

        if phases or persistence or exec_evidence:
            description_parts = []
            if phases:
                description_parts.append(f"Attack phases: {', '.join(phases)}")
            if persistence:
                svc_names = [p.get("name", "") for p in persistence[:3]]
                description_parts.append(f"Persistence via: {', '.join(svc_names)}")
            if exec_evidence:
                tools = [e.get("executable", "") for e in exec_evidence[:5]]
                description_parts.append(f"Tools used: {', '.join(tools)}")

            description = ". ".join(description_parts)

            Path(output_base + "/yara").mkdir(parents=True, exist_ok=True)
            args = [
                "--mode", "behavioral",
                "--description", description,
                "--name", f"case_{case.case_id.replace('-', '_').lower()}",
                "--severity", "high",
                "-o", output_base + "/yara/behavioral_rule.yar",
            ]
            return Decision(
                skill="yara-rule-generator",
                args=args,
                reason="Sufficient behavioral findings to generate detection rules",
                priority=4,
            )

        # IOC-based rule if we have enriched IOCs
        ioc_files = list(Path(case.case_dir).rglob("enriched_iocs.json"))
        if ioc_files:
            Path(output_base + "/yara").mkdir(parents=True, exist_ok=True)
            args = [
                "--mode", "ioc",
                "--ioc-file", str(ioc_files[0]),
                "--name", f"iocs_{case.case_id.replace('-', '_').lower()}",
                "-o", output_base + "/yara/ioc_rule.yar",
            ]
            return Decision(
                skill="yara-rule-generator",
                args=args,
                reason="Enriched IOCs available — generating IOC-based YARA rule",
                priority=4,
            )

    # ──── Priority 5: Unanalyzed evidence ────
    for ev in unanalyzed:
        ev_type = ev["type"]
        ev_path = ev["path"]

        if ev_type in ("json_log", "syslog", "plaso"):
            args = ["--inputs", ev_path, "--output-dir", output_base + "/additional_logs", "--attack-sequence"]
            return Decision(
                skill="log-timeline-correlator",
                args=args,
                reason=f"Unanalyzed evidence detected: {ev_type} at {ev_path}",
                priority=5,
            )

    # ──── No more actions → investigation may be complete ────
    return None


# ─── Report Generator ────────────────────────────────────────────────────────

def generate_report(case: CaseState) -> str:
    """Generate comprehensive investigation report from case state."""
    s = case.state
    f = s["findings"]
    sev = f["severity_summary"]

    lines = [
        f"# Investigation Report: {s['case_id']}",
        "",
        f"**Status**: {s['status']}",
        f"**Created**: {s['created']}",
        f"**Last Updated**: {s['last_updated']}",
        f"**Playbook**: {s.get('playbook', 'adaptive')}",
        f"**Total Iterations**: {s['iteration']}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Investigation conducted {s['iteration']} analysis passes across "
        f"{len(s['skills_executed'])} forensic tools ({', '.join(s['skills_executed'])}).",
        "",
    ]

    # Severity
    if sev.get("critical", 0) > 0:
        lines.append(f"**CRITICAL FINDINGS**: {sev['critical']} critical-severity indicators detected.")
    lines.append(f"Severity breakdown: Critical={sev.get('critical',0)}, High={sev.get('high',0)}, "
                 f"Medium={sev.get('medium',0)}, Low={sev.get('low',0)}")
    lines.append("")

    # Attack phases
    phases = f.get("attack_phases_detected", [])
    if phases:
        lines.append(f"**Attack Phases Detected**: {', '.join(phases)}")
        lines.append(f"**MITRE ATT&CK Techniques**: {', '.join(f.get('mitre_techniques', []))}")
        lines.append("")

    # Key findings
    lines.append("## Key Findings")
    lines.append("")

    # Execution
    exec_ev = f.get("execution_evidence", [])
    if exec_ev:
        lines.append(f"### Suspicious Executables ({len(exec_ev)})")
        for e in exec_ev[:10]:
            reasons = ', '.join(e.get('reasons', []))
            lines.append(f"- **{e.get('executable', '?')}** — sources: {', '.join(e.get('sources', []))}, "
                        f"reasons: {reasons}")
        lines.append("")

    # Persistence
    persist = f.get("persistence_mechanisms", [])
    if persist:
        lines.append(f"### Persistence Mechanisms ({len(persist)})")
        for p in persist[:10]:
            lines.append(f"- [{p.get('type', '?')}] **{p.get('name', '?')}** → `{p.get('path', '')[:80]}`")
        lines.append("")

    # IOCs
    iocs = f.get("iocs", {})
    total_iocs = sum(len(v) for v in iocs.values())
    if total_iocs > 0:
        lines.append(f"### Indicators of Compromise ({total_iocs})")
        for ioc_type, values in iocs.items():
            if values:
                lines.append(f"- **{ioc_type}**: {len(values)}")
                for v in values[:5]:
                    val = v.get("value", v) if isinstance(v, dict) else v
                    ctx = v.get("context", "") if isinstance(v, dict) else ""
                    vt = v.get("enrichment", {}).get("virustotal", {}) if isinstance(v, dict) else {}
                    mal = vt.get("malicious", "")
                    extra = f" (VT: {mal} malicious)" if mal else ""
                    extra += f" [{ctx}]" if ctx else ""
                    lines.append(f"  - `{val}`{extra}")
        lines.append("")

    # Timestomping
    ts = f.get("timestomped_files", [])
    if ts:
        lines.append(f"### Timestomped Files ({len(ts)})")
        for t in ts[:5]:
            lines.append(f"- `{t.get('full_path', t.get('filename', '?'))}`"
                        f" ({t.get('timestomp_type', '')})")
        lines.append("")

    # Brute force
    bf = f.get("bruteforce_detections", [])
    if bf:
        lines.append(f"### Brute Force / Password Spray ({len(bf)})")
        for b in bf[:5]:
            lines.append(f"- {b.get('attack_type', '?')} from **{b.get('source_ip', '?')}**: "
                        f"{b.get('total_attempts', '?')} attempts against {b.get('unique_users', '?')} users")
        lines.append("")

    # YARA rules
    yara = f.get("yara_rules_generated", [])
    if yara:
        lines.append(f"### YARA Rules Generated ({len(yara)})")
        for y in yara:
            lines.append(f"- `{y}`")
        lines.append("")

    # Investigation log
    lines.append("## Investigation Timeline")
    lines.append("")
    for entry in s.get("investigation_log", []):
        lines.append(f"**Iteration {entry['iteration']}** [{entry['timestamp']}] "
                     f"— {entry['skill']}: {entry['summary']}")
    lines.append("")

    # Human decisions
    decisions = s.get("human_decisions", [])
    if decisions:
        lines.append("## Human Decisions")
        lines.append("")
        for d in decisions:
            lines.append(f"- [{d['timestamp']}] Q: {d['question']} → A: {d['answer']}")
        lines.append("")

    # Recommendations
    lines.append("## Recommended Next Steps")
    lines.append("")
    if sev.get("critical", 0) > 0:
        lines.append("1. **Immediate**: Isolate affected hosts and disable compromised accounts")
    if iocs.get("ips"):
        lines.append("2. **Block**: Add confirmed malicious IPs/domains to firewall/proxy blocklist")
    if persist:
        lines.append("3. **Eradicate**: Remove identified persistence mechanisms from affected systems")
    if yara:
        lines.append("4. **Detect**: Deploy generated YARA rules to scanning infrastructure")
    lines.append("5. **Monitor**: Increase monitoring on affected accounts and systems for 30 days")
    lines.append("6. **Report**: File regulatory notifications if PII/sensitive data accessed")

    return "\n".join(lines)


# ─── Human-in-the-Loop ──────────────────────────────────────────────────────

def human_checkpoint(case: CaseState, reason: str, findings_summary: str,
                     proposed_action: str, auto_mode: bool = False) -> bool:
    """Present findings and get human approval. Returns True to continue."""
    if auto_mode:
        case._log(f"[AUTO] Checkpoint skipped: {reason}")
        case.record_human_decision(reason, "auto_approved")
        return True

    print("\n" + "=" * 70, file=sys.stderr)
    print(f"🔍 INVESTIGATION CHECKPOINT — {case.case_id}", file=sys.stderr)
    print(f"   Reason: {reason}", file=sys.stderr)
    print(f"   Iteration: {case.state['iteration']}", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"\n{findings_summary}\n", file=sys.stderr)
    print(f"📋 Proposed next action: {proposed_action}", file=sys.stderr)
    print("-" * 70, file=sys.stderr)

    try:
        response = input("\n[C]ontinue / [S]kip this step / [R]eport & stop / [Q]uit → ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        response = "c"  # Default to continue in non-interactive contexts

    if response in ("c", "continue", "y", "yes", ""):
        case.record_human_decision(reason, "continue")
        return True
    elif response in ("s", "skip"):
        case.record_human_decision(reason, "skip")
        return False  # Skip this action but continue investigation
    elif response in ("r", "report"):
        case.record_human_decision(reason, "report_and_stop")
        case.state["status"] = InvestigationStatus.COMPLETED.value
        case.save()
        return False
    else:
        case.record_human_decision(reason, "quit")
        case.state["status"] = InvestigationStatus.COMPLETED.value
        case.save()
        sys.exit(0)


# ─── Main Orchestration Loop ────────────────────────────────────────────────

def run_investigation(case: CaseState, evidence_dir: Path, playbook: str = None,
                      auto_mode: bool = False):
    """Main agentic investigation loop."""

    case.state["playbook"] = playbook or "adaptive"
    case.state["status"] = InvestigationStatus.IN_PROGRESS.value
    case.save()

    # Phase 1: OBSERVE — scan for evidence
    case._log("Phase: OBSERVE — Scanning for evidence...")
    evidence = scan_evidence(evidence_dir)

    if not evidence:
        case._log("No recognizable evidence found in the evidence directory.")
        print(f"[!] No evidence found in {evidence_dir}. Provide KAPE output, log files, or other artifacts.",
              file=sys.stderr)
        return

    # Register evidence sources
    for ev_type, paths in evidence.items():
        for p in paths:
            case.add_evidence(p, ev_type)

    case._log(f"Evidence found: {', '.join(f'{k}({len(v)})' for k, v in evidence.items())}")

    # Load playbook if specified
    playbook_data = None
    if playbook:
        playbook_file = SKILLS_DIR / "dfir-orchestrator" / "references" / "playbooks.json"
        if playbook_file.exists():
            all_playbooks = json.loads(playbook_file.read_text())
            playbook_data = all_playbooks.get("playbooks", {}).get(playbook)
            if playbook_data:
                case._log(f"Using playbook: {playbook_data['name']}")

    # Main loop
    stall_counter = 0
    previous_findings_count = case.get_total_findings_count()

    for iteration in range(1, MAX_ITERATIONS + 1):
        iteration_dir = case.case_dir / f"iteration_{iteration:02d}"
        iteration_dir.mkdir(parents=True, exist_ok=True)

        case._log(f"\n{'='*60}")
        case._log(f"ITERATION {iteration}/{MAX_ITERATIONS}")
        case._log(f"{'='*60}")

        # Phase 2: ORIENT — review current state
        current_findings = case.get_total_findings_count()
        if current_findings == previous_findings_count:
            stall_counter += 1
            case._log(f"No new findings in last iteration (stall counter: {stall_counter}/3)")
        else:
            stall_counter = 0
        previous_findings_count = current_findings

        if stall_counter >= 3:
            case._log("Investigation stalled — no new findings after 3 iterations")
            case.state["status"] = InvestigationStatus.STALLED.value
            case.save()
            break

        # Phase 3: DECIDE
        case._log("Phase: DECIDE — Determining next action...")
        decision = decide_next_action(case, evidence, iteration_dir)

        if decision is None:
            case._log("No more actions to take — investigation complete")
            break

        case._log(f"Decision: {decision}")

        # Periodic human checkpoint
        if iteration % CHECKPOINT_INTERVAL == 0 and not auto_mode:
            sev = case.state["findings"]["severity_summary"]
            summary = (f"After {iteration} iterations:\n"
                      f"  Findings: {current_findings} total\n"
                      f"  Severity: C={sev.get('critical',0)} H={sev.get('high',0)} "
                      f"M={sev.get('medium',0)} L={sev.get('low',0)}\n"
                      f"  Skills used: {', '.join(case.state['skills_executed'])}")
            if not human_checkpoint(case, "Periodic review", summary, str(decision), auto_mode):
                continue

        # Decision-specific checkpoint
        if decision.checkpoint:
            sev = case.state["findings"]["severity_summary"]
            summary = (f"Severity: C={sev.get('critical',0)} H={sev.get('high',0)}\n"
                      f"Phases: {', '.join(case.state['findings'].get('attack_phases_detected', []))}\n"
                      f"IOCs: {sum(len(v) for v in case.state['findings'].get('iocs', {}).values())}")
            if not human_checkpoint(case, decision.checkpoint_reason, summary,
                                   f"Run {decision.skill}", auto_mode):
                continue

        # Phase 4: ACT
        case._log(f"Phase: ACT — Executing {decision.skill}...")
        result = run_skill(decision.skill, decision.args, iteration_dir, case)

        if not result["success"]:
            case._log(f"Skill execution failed: {result.get('error', result.get('stderr', ''))[:200]}")
            case.log_action(decision.skill, " ".join(decision.args),
                           f"FAILED: {result.get('error', 'unknown error')[:100]}")
            continue

        # Phase 5: EVALUATE — parse results and update state
        case._log("Phase: EVALUATE — Parsing results...")
        new_findings = {}

        if decision.skill == "windows-artifact-triage":
            triage_dir = iteration_dir / "triage"
            if not triage_dir.exists():
                triage_dir = iteration_dir
            new_findings = parse_triage_results(triage_dir, case)
            for ev_type in ["kape_output", "evtx_csv", "prefetch_csv", "amcache_csv", "shimcache_csv"]:
                for p in evidence.get(ev_type, []):
                    case.mark_evidence_analyzed(p)

        elif decision.skill == "ioc-extractor":
            # Find the output JSON
            ioc_files = list(iteration_dir.rglob("*.json"))
            if ioc_files:
                new_findings = parse_ioc_results(ioc_files[0], case)

        elif decision.skill == "log-timeline-correlator":
            corr_dir = iteration_dir / "correlated"
            if not corr_dir.exists():
                corr_dir = iteration_dir
            new_findings = parse_timeline_results(corr_dir, case)

        elif decision.skill == "yara-rule-generator":
            yara_files = list(iteration_dir.rglob("*.yar"))
            for yf in yara_files:
                case.add_findings("yara_rules_generated", [str(yf)])
            new_findings["yara_rules"] = len(yara_files)

        # Log the action
        summary = f"New findings: {json.dumps(new_findings, default=str)[:200]}"
        case.log_action(decision.skill, " ".join(decision.args), summary,
                       result.get("output_files", []))

        case._log(f"New findings this iteration: {new_findings}")

        # Critical finding checkpoint
        sev = case.state["findings"]["severity_summary"]
        if sev.get("critical", 0) > 0 and iteration == case.state["iteration"]:
            case._log("CRITICAL FINDINGS DETECTED — requesting human review")
            if not auto_mode:
                critical_summary = (f"⚠️ CRITICAL FINDINGS:\n"
                                   f"  Severity: {sev.get('critical',0)} critical\n"
                                   f"  {json.dumps(new_findings, default=str)[:300]}")
                human_checkpoint(case, "Critical severity findings detected",
                               critical_summary, "Continue investigation", auto_mode)

    # Final report
    case._log("\nGenerating final report...")
    report = generate_report(case)
    report_path = case.case_dir / "investigation_report.md"
    report_path.write_text(report)
    case._log(f"Report written to {report_path}")

    # Export IOCs as CSV
    iocs = case.state["findings"].get("iocs", {})
    ioc_export = case.case_dir / "ioc_export.csv"
    with open(ioc_export, "w") as f:
        f.write("type,value,context,vt_malicious\n")
        for ioc_type, values in iocs.items():
            for v in values:
                val = v.get("value", v) if isinstance(v, dict) else v
                ctx = v.get("context", "") if isinstance(v, dict) else ""
                vt = v.get("enrichment", {}).get("virustotal", {}).get("malicious", "") if isinstance(v, dict) else ""
                f.write(f"{ioc_type},{val},{ctx},{vt}\n")

    case._log(f"IOC export written to {ioc_export}")

    # Export MITRE techniques
    techniques = case.state["findings"].get("mitre_techniques", [])
    if techniques:
        mitre_export = case.case_dir / "mitre_techniques.json"
        mitre_export.write_text(json.dumps({
            "case_id": case.case_id,
            "techniques": sorted(set(techniques)),
            "attack_phases": case.state["findings"].get("attack_phases_detected", []),
        }, indent=2))

    case.state["status"] = InvestigationStatus.COMPLETED.value
    case.save()

    # Print final summary
    print("\n" + report)
    return report


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DFIR Agentic Orchestrator — Autonomous forensic investigation engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode investigate --evidence-dir ./kape_output/ --case-id INC-2024-001
  %(prog)s --mode investigate --evidence-dir ./evidence/ --playbook ransomware --auto
  %(prog)s --mode resume --case-dir ./cases/INC-2024-001/
  %(prog)s --mode report --case-dir ./cases/INC-2024-001/
        """
    )
    parser.add_argument("--mode", required=True,
                        choices=["investigate", "triage", "resume", "report"],
                        help="Operating mode")
    parser.add_argument("--evidence-dir", help="Directory containing forensic evidence")
    parser.add_argument("--case-id", help="Case identifier (e.g., INC-2024-001)")
    parser.add_argument("--case-dir", help="Existing case directory (for resume/report)")
    parser.add_argument("--playbook", choices=["ransomware", "bec", "lateral_movement", "generic"],
                        help="Investigation playbook to follow")
    parser.add_argument("--auto", action="store_true",
                        help="Skip human checkpoints (batch/automated mode)")
    parser.add_argument("--output-dir", default="./cases",
                        help="Base directory for case output (default: ./cases)")

    args = parser.parse_args()

    if args.mode == "investigate" or args.mode == "triage":
        if not args.evidence_dir:
            print("Error: --evidence-dir required for investigate/triage mode", file=sys.stderr)
            sys.exit(1)
        if not args.case_id:
            args.case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        case_dir = Path(args.output_dir) / args.case_id
        case = CaseState(case_dir, args.case_id)
        evidence_dir = Path(args.evidence_dir)

        if not evidence_dir.exists():
            print(f"Error: Evidence directory not found: {evidence_dir}", file=sys.stderr)
            sys.exit(1)

        run_investigation(case, evidence_dir, playbook=args.playbook, auto_mode=args.auto)

    elif args.mode == "resume":
        if not args.case_dir:
            print("Error: --case-dir required for resume mode", file=sys.stderr)
            sys.exit(1)
        case_dir = Path(args.case_dir)
        state_file = case_dir / "case_state.json"
        if not state_file.exists():
            print(f"Error: No case state found in {case_dir}", file=sys.stderr)
            sys.exit(1)
        state = json.loads(state_file.read_text())
        case = CaseState(case_dir, state["case_id"])

        # Re-scan evidence
        evidence_sources = [e["path"] for e in state.get("evidence_sources", [])]
        evidence_dirs = set(str(Path(p).parent) for p in evidence_sources if Path(p).exists())
        if evidence_dirs:
            evidence_dir = Path(list(evidence_dirs)[0])
        else:
            print("Error: Cannot determine evidence directory from case state", file=sys.stderr)
            sys.exit(1)

        run_investigation(case, evidence_dir, playbook=state.get("playbook"),
                         auto_mode=args.auto)

    elif args.mode == "report":
        if not args.case_dir:
            print("Error: --case-dir required for report mode", file=sys.stderr)
            sys.exit(1)
        case_dir = Path(args.case_dir)
        state = json.loads((case_dir / "case_state.json").read_text())
        case = CaseState(case_dir, state["case_id"])
        report = generate_report(case)
        report_path = case_dir / "investigation_report.md"
        report_path.write_text(report)
        print(report)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
DFIR EDR Response MCP Server
CrowdStrike Falcon and Microsoft Defender XDR integration.
Read operations + containment actions with mandatory human approval.

CRITICAL: All containment/response actions require explicit human confirmation.
This server NEVER auto-executes isolation, quarantine, or remediation.

Run as MCP server: python3 -m dfir_edr_response_mcp
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("Error: 'requests' required.")

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    HAS_MCP = True
except ImportError:
    HAS_MCP = False


# ─── CrowdStrike Falcon Client ──────────────────────────────────────────────

class CrowdStrikeClient:
    def __init__(self):
        self.base_url = os.environ.get("CS_BASE_URL", "https://api.crowdstrike.com")
        self.client_id = os.environ.get("CS_CLIENT_ID", "")
        self.client_secret = os.environ.get("CS_CLIENT_SECRET", "")
        self.available = bool(self.client_id and self.client_secret)
        self._token = ""
        self._token_expiry = 0

    def _authenticate(self):
        if time.time() < self._token_expiry:
            return True
        try:
            resp = requests.post(f"{self.base_url}/oauth2/token",
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                timeout=10)
            if resp.status_code == 201:
                data = resp.json()
                self._token = data.get("access_token", "")
                self._token_expiry = time.time() + data.get("expires_in", 1799) - 60
                return True
        except Exception:
            pass
        return False

    def _headers(self):
        self._authenticate()
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def _get(self, endpoint, params=None):
        try:
            resp = requests.get(f"{self.base_url}{endpoint}",
                headers=self._headers(), params=params, timeout=15)
            return resp.json() if resp.status_code == 200 else {"error": f"HTTP {resp.status_code}", "body": resp.text[:300]}
        except Exception as e:
            return {"error": str(e)}

    def _post(self, endpoint, data):
        try:
            resp = requests.post(f"{self.base_url}{endpoint}",
                headers=self._headers(), json=data, timeout=15)
            return resp.json() if resp.status_code in (200, 201, 202) else {"error": f"HTTP {resp.status_code}", "body": resp.text[:300]}
        except Exception as e:
            return {"error": str(e)}

    # ── Read operations ──

    def get_detections(self, limit: int = 20, severity: str = None) -> dict:
        params = {"limit": limit, "sort": "last_behavior|desc"}
        if severity:
            sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            params["filter"] = f"max_severity_displayname:'{severity.capitalize()}'"
        ids_resp = self._get("/detects/queries/detects/v1", params)
        ids = ids_resp.get("resources", [])
        if not ids:
            return {"detections": [], "total": 0}
        details = self._post("/detects/entities/summaries/GET/v1", {"ids": ids[:20]})
        return {"detections": details.get("resources", []), "total": len(ids)}

    def get_host_details(self, hostname: str = None, host_id: str = None) -> dict:
        if host_id:
            return self._get(f"/devices/entities/devices/v2", {"ids": host_id})
        if hostname:
            ids_resp = self._get("/devices/queries/devices-scroll/v1",
                {"filter": f"hostname:'{hostname}'"})
            ids = ids_resp.get("resources", [])
            if ids:
                return self._get("/devices/entities/devices/v2", {"ids": ids[0]})
        return {"error": "Provide hostname or host_id"}

    def search_ioc(self, indicator: str, indicator_type: str = "sha256") -> dict:
        return self._get("/iocs/combined/indicator/v1",
            {"filter": f"type:'{indicator_type}'+value:'{indicator}'"})

    def get_incidents(self, limit: int = 20) -> dict:
        ids_resp = self._get("/incidents/queries/incidents/v1",
            {"limit": limit, "sort": "start.desc"})
        ids = ids_resp.get("resources", [])
        if not ids:
            return {"incidents": [], "total": 0}
        details = self._post("/incidents/entities/incidents/GET/v1", {"ids": ids[:20]})
        return {"incidents": details.get("resources", []), "total": len(ids)}

    # ── Response actions (REQUIRE HUMAN APPROVAL) ──

    def contain_host(self, host_id: str) -> dict:
        """Network-contain a host. REQUIRES HUMAN APPROVAL."""
        return self._post("/devices/entities/devices-actions/v2",
            {"action_parameters": [{"name": "action", "value": "contain"}],
             "ids": [host_id]})

    def lift_containment(self, host_id: str) -> dict:
        """Lift network containment. REQUIRES HUMAN APPROVAL."""
        return self._post("/devices/entities/devices-actions/v2",
            {"action_parameters": [{"name": "action", "value": "lift_containment"}],
             "ids": [host_id]})


# ─── Microsoft Defender XDR Client ───────────────────────────────────────────

class DefenderClient:
    def __init__(self):
        self.tenant_id = os.environ.get("DEFENDER_TENANT_ID", "")
        self.client_id = os.environ.get("DEFENDER_CLIENT_ID", "")
        self.client_secret = os.environ.get("DEFENDER_CLIENT_SECRET", "")
        self.available = bool(self.tenant_id and self.client_id and self.client_secret)
        self._token = ""
        self._token_expiry = 0

    def _authenticate(self):
        if time.time() < self._token_expiry:
            return True
        try:
            resp = requests.post(
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={"grant_type": "client_credentials", "client_id": self.client_id,
                      "client_secret": self.client_secret,
                      "scope": "https://api.securitycenter.microsoft.com/.default"},
                timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                self._token = data.get("access_token", "")
                self._token_expiry = time.time() + data.get("expires_in", 3599) - 60
                return True
        except Exception:
            pass
        return False

    def _headers(self):
        self._authenticate()
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def _get(self, endpoint, params=None):
        try:
            resp = requests.get(f"https://api.securitycenter.microsoft.com/api{endpoint}",
                headers=self._headers(), params=params, timeout=15)
            return resp.json() if resp.status_code == 200 else {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _post(self, endpoint, data):
        try:
            resp = requests.post(f"https://api.securitycenter.microsoft.com/api{endpoint}",
                headers=self._headers(), json=data, timeout=15)
            return resp.json() if resp.status_code in (200, 201) else {"error": f"HTTP {resp.status_code}", "body": resp.text[:300]}
        except Exception as e:
            return {"error": str(e)}

    # ── Read operations ──

    def get_alerts(self, limit: int = 20, severity: str = "High") -> dict:
        return self._get("/alerts", {"$top": limit, "$filter": f"severity eq '{severity}'",
                                      "$orderby": "alertCreationTime desc"})

    def get_machine(self, machine_id: str) -> dict:
        return self._get(f"/machines/{machine_id}")

    def find_machine(self, hostname: str) -> dict:
        return self._get("/machines", {"$filter": f"computerDnsName eq '{hostname}'"})

    def get_incidents(self, limit: int = 20) -> dict:
        return self._get("/incidents", {"$top": limit, "$orderby": "createdTime desc"})

    def advanced_hunting(self, query: str) -> dict:
        return self._post("/advancedhunting/run", {"Query": query})

    # ── Response actions (REQUIRE HUMAN APPROVAL) ──

    def isolate_machine(self, machine_id: str, comment: str = "DFIR Agent isolation") -> dict:
        """Isolate a machine from the network. REQUIRES HUMAN APPROVAL."""
        return self._post(f"/machines/{machine_id}/isolate",
            {"Comment": comment, "IsolationType": "Full"})

    def unisolate_machine(self, machine_id: str, comment: str = "DFIR Agent release") -> dict:
        return self._post(f"/machines/{machine_id}/unisolate", {"Comment": comment})

    def run_av_scan(self, machine_id: str, scan_type: str = "Quick") -> dict:
        return self._post(f"/machines/{machine_id}/runAntiVirusScan",
            {"Comment": "DFIR Agent scan", "ScanType": scan_type})

    def collect_investigation_package(self, machine_id: str) -> dict:
        return self._post(f"/machines/{machine_id}/collectInvestigationPackage",
            {"Comment": "DFIR Agent evidence collection"})


# ─── MCP Tools ───────────────────────────────────────────────────────────────

TOOLS = [
    # ── Read tools (safe, no approval needed) ──
    {
        "name": "edr_get_detections",
        "description": "Get recent detections/alerts from the configured EDR (CrowdStrike or Defender).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                "limit": {"type": "integer", "default": 20}
            }
        }
    },
    {
        "name": "edr_get_host",
        "description": "Get host/machine details by hostname or ID from the EDR platform.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string"},
                "host_id": {"type": "string"}
            }
        }
    },
    {
        "name": "edr_get_incidents",
        "description": "List recent incidents from the EDR platform.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 20}}
        }
    },
    {
        "name": "edr_search_ioc",
        "description": "Search for an IOC (hash, IP, domain) in the EDR platform's threat intelligence.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "IOC value (hash, IP, domain)"},
                "type": {"type": "string", "enum": ["sha256", "md5", "domain", "ipv4", "ipv6"], "default": "sha256"}
            },
            "required": ["indicator"]
        }
    },
    {
        "name": "edr_advanced_query",
        "description": "Run an advanced hunting query (KQL for Defender). Read-only data retrieval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "KQL query for Defender Advanced Hunting"}
            },
            "required": ["query"]
        }
    },

    # ── Response tools (REQUIRE HUMAN APPROVAL) ──
    {
        "name": "edr_contain_host",
        "description": "⚠️ RESPONSE ACTION: Network-isolate a host via EDR. THIS REQUIRES EXPLICIT HUMAN APPROVAL before execution. The host will lose network connectivity except to the EDR cloud.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host_id": {"type": "string", "description": "Host/machine ID to isolate"},
                "hostname": {"type": "string", "description": "Hostname (for confirmation display)"},
                "reason": {"type": "string", "description": "Justification for containment"},
                "human_approved": {"type": "boolean", "description": "MUST be true — confirm human approved this action", "default": False}
            },
            "required": ["host_id", "reason", "human_approved"]
        }
    },
    {
        "name": "edr_release_host",
        "description": "⚠️ RESPONSE ACTION: Remove network containment from a host. REQUIRES HUMAN APPROVAL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host_id": {"type": "string"},
                "reason": {"type": "string"},
                "human_approved": {"type": "boolean", "default": False}
            },
            "required": ["host_id", "reason", "human_approved"]
        }
    },
    {
        "name": "edr_run_scan",
        "description": "⚠️ RESPONSE ACTION: Trigger an AV scan on a host (Defender only). REQUIRES HUMAN APPROVAL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host_id": {"type": "string"},
                "scan_type": {"type": "string", "enum": ["Quick", "Full"], "default": "Quick"},
                "human_approved": {"type": "boolean", "default": False}
            },
            "required": ["host_id", "human_approved"]
        }
    },
    {
        "name": "edr_collect_evidence",
        "description": "⚠️ RESPONSE ACTION: Collect forensic investigation package from a host (Defender only). REQUIRES HUMAN APPROVAL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host_id": {"type": "string"},
                "human_approved": {"type": "boolean", "default": False}
            },
            "required": ["host_id", "human_approved"]
        }
    },
    {
        "name": "edr_status",
        "description": "Check which EDR platform is configured and available.",
        "inputSchema": {"type": "object", "properties": {}}
    },
]


def create_mcp_server():
    server = Server("dfir-edr-response")
    backend = os.environ.get("EDR_BACKEND", "crowdstrike").lower()
    cs = CrowdStrikeClient()
    defender = DefenderClient()

    @server.list_tools()
    async def list_tools():
        return [Tool(**t) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        try:
            # ── Status ──
            if name == "edr_status":
                result = {"backend": backend,
                          "crowdstrike": {"available": cs.available},
                          "defender": {"available": defender.available}}
                return [TextContent(type="text", text=json.dumps(result, indent=2))]

            # ── Safety gate for response actions ──
            response_actions = {"edr_contain_host", "edr_release_host", "edr_run_scan", "edr_collect_evidence"}
            if name in response_actions:
                if not arguments.get("human_approved", False):
                    result = {
                        "error": "BLOCKED — human_approved must be true",
                        "action": name,
                        "message": "This is a response action that requires explicit human approval. "
                                   "Set human_approved=true only after the human operator has confirmed.",
                        "host_id": arguments.get("host_id", ""),
                        "reason": arguments.get("reason", ""),
                    }
                    return [TextContent(type="text", text=json.dumps(result, indent=2))]

            # ── Read operations ──
            if name == "edr_get_detections":
                if backend == "crowdstrike" and cs.available:
                    result = cs.get_detections(arguments.get("limit", 20), arguments.get("severity"))
                elif backend == "defender" and defender.available:
                    result = defender.get_alerts(arguments.get("limit", 20),
                                                arguments.get("severity", "High").capitalize())
                else:
                    result = {"error": f"EDR '{backend}' not configured"}

            elif name == "edr_get_host":
                if backend == "crowdstrike" and cs.available:
                    result = cs.get_host_details(arguments.get("hostname"), arguments.get("host_id"))
                elif backend == "defender" and defender.available:
                    if arguments.get("host_id"):
                        result = defender.get_machine(arguments["host_id"])
                    else:
                        result = defender.find_machine(arguments.get("hostname", ""))
                else:
                    result = {"error": f"EDR '{backend}' not configured"}

            elif name == "edr_get_incidents":
                if backend == "crowdstrike" and cs.available:
                    result = cs.get_incidents(arguments.get("limit", 20))
                elif backend == "defender" and defender.available:
                    result = defender.get_incidents(arguments.get("limit", 20))
                else:
                    result = {"error": f"EDR '{backend}' not configured"}

            elif name == "edr_search_ioc":
                if backend == "crowdstrike" and cs.available:
                    result = cs.search_ioc(arguments["indicator"], arguments.get("type", "sha256"))
                else:
                    result = {"error": "IOC search currently supported on CrowdStrike only"}

            elif name == "edr_advanced_query":
                if backend == "defender" and defender.available:
                    result = defender.advanced_hunting(arguments["query"])
                else:
                    result = {"error": "Advanced hunting supported on Defender only"}

            # ── Response actions (human_approved already verified above) ──
            elif name == "edr_contain_host":
                host_id = arguments["host_id"]
                if backend == "crowdstrike" and cs.available:
                    result = cs.contain_host(host_id)
                elif backend == "defender" and defender.available:
                    result = defender.isolate_machine(host_id, arguments.get("reason", ""))
                else:
                    result = {"error": f"EDR '{backend}' not configured"}
                result["_audit"] = {"action": "contain", "host_id": host_id,
                                    "reason": arguments.get("reason", ""),
                                    "timestamp": datetime.now(timezone.utc).isoformat()}

            elif name == "edr_release_host":
                host_id = arguments["host_id"]
                if backend == "crowdstrike" and cs.available:
                    result = cs.lift_containment(host_id)
                elif backend == "defender" and defender.available:
                    result = defender.unisolate_machine(host_id, arguments.get("reason", ""))
                else:
                    result = {"error": f"EDR '{backend}' not configured"}

            elif name == "edr_run_scan":
                if backend == "defender" and defender.available:
                    result = defender.run_av_scan(arguments["host_id"], arguments.get("scan_type", "Quick"))
                else:
                    result = {"error": "AV scan supported on Defender only"}

            elif name == "edr_collect_evidence":
                if backend == "defender" and defender.available:
                    result = defender.collect_investigation_package(arguments["host_id"])
                else:
                    result = {"error": "Evidence collection supported on Defender only"}

            else:
                result = {"error": f"Unknown tool: {name}"}

            return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    return server


async def main():
    if not HAS_MCP:
        sys.exit("Error: MCP SDK required. Install: pip install mcp --break-system-packages")
    server = create_mcp_server()
    async with stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

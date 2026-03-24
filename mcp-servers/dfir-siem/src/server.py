#!/usr/bin/env python3
"""
DFIR SIEM MCP Server
Query and receive alerts from Splunk, Elastic, and Wazuh.

Run as MCP server: python3 -m dfir_siem_mcp
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("Error: 'requests' required.", file=sys.stderr)
    sys.exit(1)

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    HAS_MCP = True
except ImportError:
    HAS_MCP = False


# ─── SIEM Clients ────────────────────────────────────────────────────────────

class SplunkClient:
    def __init__(self):
        self.host = os.environ.get("SPLUNK_HOST", "")
        self.token = os.environ.get("SPLUNK_TOKEN", "")
        self.verify_ssl = os.environ.get("SPLUNK_VERIFY_SSL", "false").lower() == "true"
        self.available = bool(self.host and self.token)

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def search(self, query: str, earliest: str = "-24h", latest: str = "now", max_results: int = 100) -> dict:
        if not self.available:
            return {"error": "Splunk not configured"}
        try:
            # Create search job
            resp = requests.post(
                f"{self.host}/services/search/jobs",
                headers=self._headers(),
                data={"search": f"search {query}", "earliest_time": earliest,
                      "latest_time": latest, "output_mode": "json", "max_count": max_results},
                verify=self.verify_ssl, timeout=30)
            if resp.status_code != 201:
                return {"error": f"Splunk search creation failed: {resp.status_code}"}
            sid = resp.json().get("sid", "")

            # Poll for results
            for _ in range(60):
                status_resp = requests.get(
                    f"{self.host}/services/search/jobs/{sid}",
                    headers=self._headers(), params={"output_mode": "json"},
                    verify=self.verify_ssl, timeout=10)
                state = status_resp.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
                if state == "DONE":
                    break
                time.sleep(2)

            # Get results
            results_resp = requests.get(
                f"{self.host}/services/search/jobs/{sid}/results",
                headers=self._headers(), params={"output_mode": "json", "count": max_results},
                verify=self.verify_ssl, timeout=30)
            return results_resp.json()
        except Exception as e:
            return {"error": str(e)}

    def get_notable_events(self, earliest: str = "-1h", severity: str = "critical") -> dict:
        query = f'`notable` | where urgency="{severity}" | head 50'
        return self.search(query, earliest=earliest)

    def get_alerts(self, max_results: int = 20) -> dict:
        if not self.available:
            return {"error": "Splunk not configured"}
        try:
            resp = requests.get(
                f"{self.host}/services/alerts/fired_alerts",
                headers=self._headers(), params={"output_mode": "json", "count": max_results},
                verify=self.verify_ssl, timeout=15)
            return resp.json()
        except Exception as e:
            return {"error": str(e)}


class ElasticClient:
    def __init__(self):
        self.host = os.environ.get("ELASTIC_HOST", "")
        self.api_key = os.environ.get("ELASTIC_API_KEY", "")
        self.verify_ssl = os.environ.get("ELASTIC_VERIFY_SSL", "false").lower() == "true"
        self.available = bool(self.host and self.api_key)

    def _headers(self):
        return {"Authorization": f"ApiKey {self.api_key}", "Content-Type": "application/json"}

    def search(self, index: str, query_dsl: dict, size: int = 100) -> dict:
        if not self.available:
            return {"error": "Elastic not configured"}
        try:
            resp = requests.post(
                f"{self.host}/{index}/_search",
                headers=self._headers(), json={"query": query_dsl, "size": size, "sort": [{"@timestamp": "desc"}]},
                verify=self.verify_ssl, timeout=30)
            data = resp.json()
            hits = data.get("hits", {}).get("hits", [])
            return {"total": data.get("hits", {}).get("total", {}).get("value", 0),
                    "results": [h.get("_source", {}) for h in hits]}
        except Exception as e:
            return {"error": str(e)}

    def kql_search(self, index: str, kql: str, time_range: str = "now-24h", size: int = 100) -> dict:
        query_dsl = {
            "bool": {
                "must": [{"query_string": {"query": kql}},
                         {"range": {"@timestamp": {"gte": time_range}}}]
            }
        }
        return self.search(index, query_dsl, size)

    def get_security_alerts(self, severity: str = "critical", size: int = 20) -> dict:
        return self.kql_search(
            ".siem-signals-*",
            f'signal.rule.severity: "{severity}"',
            size=size
        )


class WazuhClient:
    def __init__(self):
        self.host = os.environ.get("WAZUH_HOST", "")
        self.user = os.environ.get("WAZUH_USER", "")
        self.password = os.environ.get("WAZUH_PASSWORD", "")
        self.verify_ssl = os.environ.get("WAZUH_VERIFY_SSL", "false").lower() == "true"
        self.token = ""
        self.available = bool(self.host and self.user and self.password)

    def _authenticate(self):
        try:
            resp = requests.post(
                f"{self.host}/security/user/authenticate",
                auth=HTTPBasicAuth(self.user, self.password),
                verify=self.verify_ssl, timeout=10)
            if resp.status_code == 200:
                self.token = resp.json().get("data", {}).get("token", "")
        except Exception:
            pass

    def _headers(self):
        if not self.token:
            self._authenticate()
        return {"Authorization": f"Bearer {self.token}"}

    def get_alerts(self, limit: int = 20, level_min: int = 12) -> dict:
        if not self.available:
            return {"error": "Wazuh not configured"}
        try:
            resp = requests.get(
                f"{self.host}/alerts",
                headers=self._headers(),
                params={"limit": limit, "sort": "-timestamp", "q": f"rule.level>{level_min}"},
                verify=self.verify_ssl, timeout=15)
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def get_agent_info(self, agent_id: str) -> dict:
        if not self.available:
            return {"error": "Wazuh not configured"}
        try:
            resp = requests.get(
                f"{self.host}/agents/{agent_id}",
                headers=self._headers(),
                verify=self.verify_ssl, timeout=10)
            return resp.json()
        except Exception as e:
            return {"error": str(e)}


# ─── MCP Tool Definitions ───────────────────────────────────────────────────

TOOLS = [
    {
        "name": "siem_search",
        "description": "Execute a search query against the configured SIEM (Splunk SPL, Elastic KQL, or Wazuh API). Returns matching events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (SPL for Splunk, KQL for Elastic)"},
                "time_range": {"type": "string", "description": "Time range (e.g., '-24h', 'now-1h', '2024-06-15T00:00:00Z')", "default": "-24h"},
                "max_results": {"type": "integer", "description": "Maximum results to return", "default": 100},
                "index": {"type": "string", "description": "Index/sourcetype to search (Elastic only)", "default": "*"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "siem_get_alerts",
        "description": "Get recent security alerts from the configured SIEM. Returns critical/high severity alerts for immediate triage.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "default": "critical"},
                "max_results": {"type": "integer", "default": 20},
                "time_range": {"type": "string", "default": "-1h"}
            }
        }
    },
    {
        "name": "siem_check_status",
        "description": "Check which SIEM backend is configured and available.",
        "inputSchema": {"type": "object", "properties": {}}
    },
]


def create_mcp_server():
    server = Server("dfir-siem")
    backend = os.environ.get("SIEM_BACKEND", "splunk").lower()
    splunk = SplunkClient()
    elastic = ElasticClient()
    wazuh = WazuhClient()

    @server.list_tools()
    async def list_tools():
        return [Tool(**t) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        try:
            if name == "siem_search":
                query = arguments["query"]
                time_range = arguments.get("time_range", "-24h")
                max_results = arguments.get("max_results", 100)

                if backend == "splunk" and splunk.available:
                    result = splunk.search(query, earliest=time_range, max_results=max_results)
                elif backend == "elastic" and elastic.available:
                    index = arguments.get("index", "*")
                    result = elastic.kql_search(index, query, time_range=time_range, size=max_results)
                elif backend == "wazuh" and wazuh.available:
                    result = wazuh.get_alerts(limit=max_results)
                else:
                    result = {"error": f"SIEM backend '{backend}' not configured"}

            elif name == "siem_get_alerts":
                severity = arguments.get("severity", "critical")
                max_results = arguments.get("max_results", 20)

                if backend == "splunk" and splunk.available:
                    result = splunk.get_notable_events(severity=severity)
                elif backend == "elastic" and elastic.available:
                    result = elastic.get_security_alerts(severity=severity, size=max_results)
                elif backend == "wazuh" and wazuh.available:
                    level_map = {"critical": 14, "high": 12, "medium": 7, "low": 3}
                    result = wazuh.get_alerts(limit=max_results, level_min=level_map.get(severity, 12))
                else:
                    result = {"error": f"SIEM backend '{backend}' not configured"}

            elif name == "siem_check_status":
                result = {
                    "configured_backend": backend,
                    "splunk": {"available": splunk.available, "host": splunk.host},
                    "elastic": {"available": elastic.available, "host": elastic.host},
                    "wazuh": {"available": wazuh.available, "host": wazuh.host},
                }
            else:
                result = {"error": f"Unknown tool: {name}"}

            return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    return server


async def main():
    if not HAS_MCP:
        print("Error: MCP SDK required. Install: pip install mcp --break-system-packages", file=sys.stderr)
        sys.exit(1)
    server = create_mcp_server()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

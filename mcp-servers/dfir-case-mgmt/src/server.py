#!/usr/bin/env python3
"""
DFIR Case Management MCP Server
CRUD operations for TheHive and IRIS DFIR: cases, alerts, tasks, observables.

Run as MCP server: python3 -m dfir_case_mgmt_mcp
"""

import json
import os
import sys
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


# ─── TheHive Client ──────────────────────────────────────────────────────────

class TheHiveClient:
    def __init__(self):
        self.url = os.environ.get("THEHIVE_URL", "").rstrip("/")
        self.api_key = os.environ.get("THEHIVE_API_KEY", "")
        self.available = bool(self.url and self.api_key)

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def _post(self, endpoint, data):
        try:
            resp = requests.post(f"{self.url}/api/v1{endpoint}",
                                headers=self._headers(), json=data, timeout=15)
            return resp.json() if resp.status_code in (200, 201) else {"error": f"HTTP {resp.status_code}", "body": resp.text[:300]}
        except Exception as e:
            return {"error": str(e)}

    def _get(self, endpoint, params=None):
        try:
            resp = requests.get(f"{self.url}/api/v1{endpoint}",
                               headers=self._headers(), params=params, timeout=15)
            return resp.json() if resp.status_code == 200 else {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def create_case(self, title: str, description: str, severity: int = 2,
                    tlp: int = 2, tags: list = None) -> dict:
        return self._post("/case", {
            "title": title, "description": description,
            "severity": severity, "tlp": tlp,
            "tags": tags or [], "flag": False, "status": "Open",
        })

    def create_alert(self, title: str, description: str, source: str = "DFIR-Agent",
                     severity: int = 2, type_: str = "dfir-auto", tags: list = None) -> dict:
        return self._post("/alert", {
            "title": title, "description": description,
            "source": source, "sourceRef": f"dfir-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "type": type_, "severity": severity, "tags": tags or [],
        })

    def add_observable(self, case_id: str, data_type: str, data: str,
                       message: str = "", tlp: int = 2, is_ioc: bool = True) -> dict:
        return self._post(f"/case/{case_id}/observable", {
            "dataType": data_type, "data": data,
            "message": message, "tlp": tlp, "ioc": is_ioc, "sighted": True,
        })

    def create_task(self, case_id: str, title: str, description: str = "",
                    status: str = "Waiting", group: str = "default") -> dict:
        return self._post(f"/case/{case_id}/task", {
            "title": title, "description": description,
            "status": status, "group": group,
        })

    def get_case(self, case_id: str) -> dict:
        return self._get(f"/case/{case_id}")

    def list_cases(self, status: str = "Open", limit: int = 20) -> dict:
        return self._post("/case/_search", {
            "query": {"_and": [{"status": status}]},
            "range": f"0-{limit}", "sort": ["-createdAt"],
        })

    def add_case_comment(self, case_id: str, message: str) -> dict:
        return self._post(f"/case/{case_id}/comment", {"message": message})


# ─── IRIS Client ─────────────────────────────────────────────────────────────

class IRISClient:
    def __init__(self):
        self.url = os.environ.get("IRIS_URL", "").rstrip("/")
        self.api_key = os.environ.get("IRIS_API_KEY", "")
        self.available = bool(self.url and self.api_key)

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def _post(self, endpoint, data):
        try:
            resp = requests.post(f"{self.url}/api/v2{endpoint}",
                                headers=self._headers(), json=data, timeout=15, verify=False)
            return resp.json() if resp.status_code in (200, 201) else {"error": f"HTTP {resp.status_code}", "body": resp.text[:300]}
        except Exception as e:
            return {"error": str(e)}

    def _get(self, endpoint, params=None):
        try:
            resp = requests.get(f"{self.url}/api/v2{endpoint}",
                               headers=self._headers(), params=params, timeout=15, verify=False)
            return resp.json() if resp.status_code == 200 else {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def create_case(self, name: str, description: str, severity: int = 3,
                    customer_id: int = 1) -> dict:
        return self._post("/cases", {
            "case_name": name, "case_description": description,
            "case_severity_id": severity, "case_customer": customer_id,
        })

    def add_ioc(self, case_id: int, ioc_type: int, ioc_value: str,
                description: str = "", tlp_id: int = 2) -> dict:
        return self._post(f"/cases/{case_id}/iocs", {
            "ioc_type_id": ioc_type, "ioc_value": ioc_value,
            "ioc_description": description, "ioc_tlp_id": tlp_id, "ioc_tags": "",
        })

    def add_note(self, case_id: int, title: str, content: str, group_id: int = 1) -> dict:
        return self._post(f"/cases/{case_id}/notes", {
            "note_title": title, "note_content": content, "group_id": group_id,
        })

    def get_case(self, case_id: int) -> dict:
        return self._get(f"/cases/{case_id}")

    def list_cases(self) -> dict:
        return self._get("/cases")


# ─── MCP Tools ───────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "create_case",
        "description": "Create a new incident case in TheHive or IRIS. Returns the case ID for subsequent operations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Case title"},
                "description": {"type": "string", "description": "Case description with investigation context"},
                "severity": {"type": "integer", "description": "1=low, 2=medium, 3=high, 4=critical", "default": 2},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for categorization"}
            },
            "required": ["title", "description"]
        }
    },
    {
        "name": "create_alert",
        "description": "Create an alert in TheHive (can be promoted to a case later). Use for automated alert ingestion.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "severity": {"type": "integer", "default": 2},
                "source": {"type": "string", "default": "DFIR-Agent"},
                "tags": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["title", "description"]
        }
    },
    {
        "name": "add_observable",
        "description": "Add an IOC/observable to an existing case (IP, domain, hash, URL, email, filename, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "Case ID"},
                "data_type": {"type": "string", "enum": ["ip", "domain", "url", "hash", "mail", "filename", "fqdn", "uri_path", "user-agent", "other"]},
                "data": {"type": "string", "description": "The observable value"},
                "message": {"type": "string", "description": "Context about where/how this was found"},
                "is_ioc": {"type": "boolean", "default": True}
            },
            "required": ["case_id", "data_type", "data"]
        }
    },
    {
        "name": "add_task",
        "description": "Add an investigation task to a case (e.g., 'Analyze memory dump', 'Review Okta logs').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string", "default": ""},
                "status": {"type": "string", "enum": ["Waiting", "InProgress", "Completed", "Cancel"], "default": "Waiting"}
            },
            "required": ["case_id", "title"]
        }
    },
    {
        "name": "add_case_comment",
        "description": "Add an investigation note/comment to an existing case. Use for logging findings from each analysis step.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"},
                "message": {"type": "string", "description": "Comment content (supports Markdown)"}
            },
            "required": ["case_id", "message"]
        }
    },
    {
        "name": "get_case",
        "description": "Get details of an existing case by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {"case_id": {"type": "string"}},
            "required": ["case_id"]
        }
    },
    {
        "name": "list_cases",
        "description": "List open/recent cases.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "default": "Open"},
                "limit": {"type": "integer", "default": 20}
            }
        }
    },
    {
        "name": "case_mgmt_status",
        "description": "Check which case management platform is configured.",
        "inputSchema": {"type": "object", "properties": {}}
    },
]


def create_mcp_server():
    server = Server("dfir-case-mgmt")
    backend = os.environ.get("CASE_BACKEND", "thehive").lower()
    thehive = TheHiveClient()
    iris = IRISClient()

    @server.list_tools()
    async def list_tools():
        return [Tool(**t) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        try:
            if name == "case_mgmt_status":
                result = {"backend": backend,
                          "thehive": {"available": thehive.available, "url": thehive.url},
                          "iris": {"available": iris.available, "url": iris.url}}
            elif backend == "thehive" and thehive.available:
                if name == "create_case":
                    result = thehive.create_case(arguments["title"], arguments["description"],
                                                 arguments.get("severity", 2), tags=arguments.get("tags"))
                elif name == "create_alert":
                    result = thehive.create_alert(arguments["title"], arguments["description"],
                                                  arguments.get("source", "DFIR-Agent"),
                                                  arguments.get("severity", 2), tags=arguments.get("tags"))
                elif name == "add_observable":
                    result = thehive.add_observable(arguments["case_id"], arguments["data_type"],
                                                    arguments["data"], arguments.get("message", ""),
                                                    is_ioc=arguments.get("is_ioc", True))
                elif name == "add_task":
                    result = thehive.create_task(arguments["case_id"], arguments["title"],
                                                 arguments.get("description", ""), arguments.get("status", "Waiting"))
                elif name == "add_case_comment":
                    result = thehive.add_case_comment(arguments["case_id"], arguments["message"])
                elif name == "get_case":
                    result = thehive.get_case(arguments["case_id"])
                elif name == "list_cases":
                    result = thehive.list_cases(arguments.get("status", "Open"), arguments.get("limit", 20))
                else:
                    result = {"error": f"Unknown tool: {name}"}
            elif backend == "iris" and iris.available:
                case_id = int(arguments.get("case_id", 0)) if "case_id" in arguments else 0
                if name == "create_case":
                    result = iris.create_case(arguments["title"], arguments["description"],
                                              arguments.get("severity", 3))
                elif name == "add_observable":
                    type_map = {"ip": 76, "domain": 20, "hash": 113, "url": 141,
                                "mail": 77, "filename": 30, "fqdn": 20}
                    ioc_type = type_map.get(arguments["data_type"], 150)
                    result = iris.add_ioc(case_id, ioc_type, arguments["data"],
                                          arguments.get("message", ""))
                elif name == "add_case_comment":
                    result = iris.add_note(case_id, "Investigation Note", arguments["message"])
                elif name == "get_case":
                    result = iris.get_case(case_id)
                elif name == "list_cases":
                    result = iris.list_cases()
                else:
                    result = {"error": f"Tool '{name}' not supported on IRIS backend"}
            else:
                result = {"error": f"Backend '{backend}' not configured"}

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

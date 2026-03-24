#!/usr/bin/env python3
"""
DFIR Threat Intelligence MCP Server
Unified interface to VirusTotal, Shodan, AbuseIPDB, GreyNoise, AlienVault OTX.

Run as MCP server: python3 -m dfir_threatintel_mcp
Or standalone test: python3 -m dfir_threatintel_mcp --test
"""

import json
import os
import sys
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' required. Install: pip install requests --break-system-packages", file=sys.stderr)
    sys.exit(1)

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

# ─── API Clients ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple per-service rate limiter."""
    def __init__(self):
        self._last_call = {}
        self._delays = {
            "virustotal": 15.5,  # Free tier: 4/min
            "shodan": 1.0,
            "abuseipdb": 0.1,   # 1000/day
            "greynoise": 1.0,
            "otx": 0.5,
        }

    def wait(self, service: str):
        delay = self._delays.get(service, 1.0)
        last = self._last_call.get(service, 0)
        elapsed = time.time() - last
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_call[service] = time.time()


class ThreatIntelClient:
    """Unified threat intel API client."""

    def __init__(self):
        self.limiter = RateLimiter()
        self.apis = {
            "virustotal": os.environ.get("VT_API_KEY", ""),
            "shodan": os.environ.get("SHODAN_API_KEY", ""),
            "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", ""),
            "greynoise": os.environ.get("GREYNOISE_API_KEY", ""),
            "otx": os.environ.get("OTX_API_KEY", ""),
        }
        self.available = {k: bool(v) for k, v in self.apis.items()}

    def _get(self, service, url, headers=None, params=None, timeout=15):
        self.limiter.wait(service)
        try:
            resp = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            return {"error": f"HTTP {resp.status_code}", "body": resp.text[:200]}
        except requests.RequestException as e:
            return {"error": str(e)}

    # ── VirusTotal ──

    def vt_lookup_hash(self, file_hash: str) -> dict:
        if not self.available["virustotal"]:
            return {"error": "VT_API_KEY not set"}
        data = self._get("virustotal",
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": self.apis["virustotal"]})
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "hash": file_hash,
            "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "type": attrs.get("type_description", ""),
            "names": attrs.get("names", [])[:5],
            "tags": attrs.get("tags", [])[:10],
            "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
            "first_submission": attrs.get("first_submission_date", ""),
            "last_analysis": attrs.get("last_analysis_date", ""),
        }

    def vt_lookup_ip(self, ip: str) -> dict:
        if not self.available["virustotal"]:
            return {"error": "VT_API_KEY not set"}
        data = self._get("virustotal",
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self.apis["virustotal"]})
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "reputation": attrs.get("reputation", 0),
        }

    def vt_lookup_domain(self, domain: str) -> dict:
        if not self.available["virustotal"]:
            return {"error": "VT_API_KEY not set"}
        data = self._get("virustotal",
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": self.apis["virustotal"]})
        if "error" in data:
            return data
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "registrar": attrs.get("registrar", ""),
            "creation_date": attrs.get("creation_date", ""),
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
        }

    # ── Shodan ──

    def shodan_lookup_ip(self, ip: str) -> dict:
        if not self.available["shodan"]:
            return {"error": "SHODAN_API_KEY not set"}
        data = self._get("shodan",
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": self.apis["shodan"]})
        if "error" in data:
            return data
        return {
            "ip": ip,
            "os": data.get("os", ""),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", [])[:10],
            "hostnames": data.get("hostnames", []),
            "last_update": data.get("last_update", ""),
        }

    # ── AbuseIPDB ──

    def abuseipdb_check(self, ip: str) -> dict:
        if not self.available["abuseipdb"]:
            return {"error": "ABUSEIPDB_API_KEY not set"}
        data = self._get("abuseipdb",
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.apis["abuseipdb"], "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
        if "error" in data:
            return data
        d = data.get("data", {})
        return {
            "ip": ip,
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "isp": d.get("isp", ""),
            "country": d.get("countryCode", ""),
            "usage_type": d.get("usageType", ""),
            "is_tor": d.get("isTor", False),
            "is_whitelisted": d.get("isWhitelisted", False),
            "last_reported": d.get("lastReportedAt", ""),
        }

    # ── GreyNoise ──

    def greynoise_check(self, ip: str) -> dict:
        if not self.available["greynoise"]:
            return {"error": "GREYNOISE_API_KEY not set"}
        data = self._get("greynoise",
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": self.apis["greynoise"]})
        if "error" in data:
            return data
        return {
            "ip": ip,
            "classification": data.get("classification", "unknown"),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "name": data.get("name", ""),
            "message": data.get("message", ""),
        }

    # ── OTX ──

    def otx_lookup_indicator(self, indicator_type: str, indicator: str) -> dict:
        if not self.available["otx"]:
            return {"error": "OTX_API_KEY not set"}
        type_map = {"ip": "IPv4", "domain": "domain", "hostname": "hostname",
                    "url": "url", "hash": "file"}
        otx_type = type_map.get(indicator_type, indicator_type)
        section = "general"
        data = self._get("otx",
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/{section}",
            headers={"X-OTX-API-KEY": self.apis["otx"]})
        if "error" in data:
            return data
        return {
            "indicator": indicator,
            "type": indicator_type,
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "pulses": [{"name": p.get("name", ""), "tags": p.get("tags", [])[:5]}
                      for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
            "country": data.get("country_name", ""),
            "reputation": data.get("reputation", 0),
        }

    # ── Unified lookup ──

    def enrich_ip(self, ip: str) -> dict:
        """Enrich an IP across all available services."""
        result = {"ip": ip, "enrichment": {}, "verdict": "unknown"}
        if self.available["virustotal"]:
            result["enrichment"]["virustotal"] = self.vt_lookup_ip(ip)
        if self.available["abuseipdb"]:
            result["enrichment"]["abuseipdb"] = self.abuseipdb_check(ip)
        if self.available["shodan"]:
            result["enrichment"]["shodan"] = self.shodan_lookup_ip(ip)
        if self.available["greynoise"]:
            result["enrichment"]["greynoise"] = self.greynoise_check(ip)
        if self.available["otx"]:
            result["enrichment"]["otx"] = self.otx_lookup_indicator("ip", ip)

        # Compute verdict
        vt_mal = result["enrichment"].get("virustotal", {}).get("malicious", 0)
        abuse_score = result["enrichment"].get("abuseipdb", {}).get("abuse_confidence", 0)
        gn_class = result["enrichment"].get("greynoise", {}).get("classification", "")

        if vt_mal > 5 or abuse_score > 80:
            result["verdict"] = "malicious"
        elif vt_mal > 0 or abuse_score > 30 or gn_class == "malicious":
            result["verdict"] = "suspicious"
        elif gn_class == "benign" or result["enrichment"].get("greynoise", {}).get("riot"):
            result["verdict"] = "benign"

        return result

    def enrich_hash(self, file_hash: str) -> dict:
        """Enrich a file hash across available services."""
        result = {"hash": file_hash, "enrichment": {}, "verdict": "unknown"}
        if self.available["virustotal"]:
            result["enrichment"]["virustotal"] = self.vt_lookup_hash(file_hash)
        if self.available["otx"]:
            result["enrichment"]["otx"] = self.otx_lookup_indicator("hash", file_hash)

        vt = result["enrichment"].get("virustotal", {})
        if vt.get("malicious", 0) > 5:
            result["verdict"] = "malicious"
        elif vt.get("malicious", 0) > 0:
            result["verdict"] = "suspicious"
        elif vt.get("undetected", 0) > 50:
            result["verdict"] = "clean"

        return result

    def enrich_domain(self, domain: str) -> dict:
        """Enrich a domain across available services."""
        result = {"domain": domain, "enrichment": {}, "verdict": "unknown"}
        if self.available["virustotal"]:
            result["enrichment"]["virustotal"] = self.vt_lookup_domain(domain)
        if self.available["otx"]:
            result["enrichment"]["otx"] = self.otx_lookup_indicator("domain", domain)

        vt = result["enrichment"].get("virustotal", {})
        if vt.get("malicious", 0) > 5:
            result["verdict"] = "malicious"
        elif vt.get("malicious", 0) > 0:
            result["verdict"] = "suspicious"

        return result


# ─── MCP Server Definition ──────────────────────────────────────────────────

TOOLS = [
    {
        "name": "enrich_ip",
        "description": "Enrich an IP address across all configured threat intel services (VirusTotal, AbuseIPDB, Shodan, GreyNoise, OTX). Returns unified verdict: malicious/suspicious/benign/unknown.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to enrich"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "enrich_hash",
        "description": "Enrich a file hash (MD5/SHA1/SHA256) against VirusTotal and OTX. Returns detection ratio, threat classification, and verdict.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string", "description": "File hash (MD5, SHA1, or SHA256)"}
            },
            "required": ["hash"]
        }
    },
    {
        "name": "enrich_domain",
        "description": "Enrich a domain against VirusTotal and OTX. Returns reputation, categories, and verdict.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name to enrich"}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "shodan_host",
        "description": "Get Shodan host information: open ports, services, vulnerabilities, geolocation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to look up on Shodan"}
            },
            "required": ["ip"]
        }
    },
    {
        "name": "bulk_enrich",
        "description": "Enrich multiple IOCs at once. Accepts a list of {type, value} objects. Types: ip, hash, domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "indicators": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "enum": ["ip", "hash", "domain"]},
                            "value": {"type": "string"}
                        },
                        "required": ["type", "value"]
                    },
                    "description": "List of indicators to enrich"
                }
            },
            "required": ["indicators"]
        }
    },
    {
        "name": "check_available_services",
        "description": "Check which threat intel services are configured and available.",
        "inputSchema": {"type": "object", "properties": {}}
    },
]


def create_mcp_server():
    """Create and configure the MCP server."""
    server = Server("dfir-threatintel")
    client = ThreatIntelClient()

    @server.list_tools()
    async def list_tools():
        return [Tool(**t) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        try:
            if name == "enrich_ip":
                result = client.enrich_ip(arguments["ip"])
            elif name == "enrich_hash":
                result = client.enrich_hash(arguments["hash"])
            elif name == "enrich_domain":
                result = client.enrich_domain(arguments["domain"])
            elif name == "shodan_host":
                result = client.shodan_lookup_ip(arguments["ip"])
            elif name == "bulk_enrich":
                results = []
                for ind in arguments["indicators"]:
                    if ind["type"] == "ip":
                        results.append(client.enrich_ip(ind["value"]))
                    elif ind["type"] == "hash":
                        results.append(client.enrich_hash(ind["value"]))
                    elif ind["type"] == "domain":
                        results.append(client.enrich_domain(ind["value"]))
                result = {"enriched": results, "total": len(results)}
            elif name == "check_available_services":
                result = client.available
            else:
                result = {"error": f"Unknown tool: {name}"}

            return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    return server


# ─── Entry Point ─────────────────────────────────────────────────────────────

async def main():
    if not HAS_MCP:
        print("Error: MCP SDK required. Install: pip install mcp --break-system-packages", file=sys.stderr)
        sys.exit(1)
    server = create_mcp_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def test_mode():
    """Test the client without MCP."""
    client = ThreatIntelClient()
    print(f"Available services: {client.available}")
    print("\nTesting IP enrichment (1.1.1.1):")
    if client.available.get("greynoise"):
        print(json.dumps(client.greynoise_check("1.1.1.1"), indent=2))
    else:
        print("  No API keys configured — set VT_API_KEY, SHODAN_API_KEY, etc.")
    print("\nTo run as MCP server: python3 -m dfir_threatintel_mcp")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test_mode()
    else:
        import asyncio
        asyncio.run(main())

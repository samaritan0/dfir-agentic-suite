"""DFIR dfir-siem MCP Server — run with: python3 -m dfir_siem_mcp"""
import sys, os, asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from server import main
asyncio.run(main())

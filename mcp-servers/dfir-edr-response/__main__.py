"""DFIR dfir-edr-response MCP Server — run with: python3 -m dfir_edr_response_mcp"""
import sys, os, asyncio
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from server import main
asyncio.run(main())

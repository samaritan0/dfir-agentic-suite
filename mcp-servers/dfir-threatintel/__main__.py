"""DFIR Threat Intelligence MCP Server — run with: python3 -m dfir_threatintel_mcp"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from server import main, test_mode
import asyncio

if "--test" in sys.argv:
    test_mode()
else:
    asyncio.run(main())

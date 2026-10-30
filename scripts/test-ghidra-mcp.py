#!/usr/bin/env python3
"""End-to-end stdio MCP smoke test for the containerized Ghidra bridge."""

import asyncio
import os

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    environment = os.environ.copy()
    environment["GHIDRA_MCP_URL"] = "http://127.0.0.1:8089"
    server = StdioServerParameters(
        command="/opt/ghidra-mcp/venv/bin/bridge-mcp-ghidra",
        args=["--transport", "stdio"],
        env=environment,
    )
    async with stdio_client(server) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            initialized = await session.initialize()
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            required = {"search_tools", "list_tool_groups", "find_functions", "get_functions"}
            missing = sorted(required - names)
            if missing:
                raise RuntimeError(f"Expected MCP tools are missing: {', '.join(missing)}")
            print(f"server={initialized.serverInfo.name} version={initialized.serverInfo.version}")
            print(f"advertised_tools={len(names)} lazy_loading=true")


if __name__ == "__main__":
    asyncio.run(main())

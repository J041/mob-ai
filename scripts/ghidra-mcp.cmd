@echo off
setlocal
pushd "%~dp0.."

docker compose up -d --build --wait --wait-timeout 180 1>&2
if errorlevel 1 goto :failed

docker compose exec -T ^
  -e GHIDRA_MCP_URL=http://127.0.0.1:18089 ^
  -e GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1 ^
  worker ^
  /opt/ghidra-mcp/venv/bin/bridge-mcp-ghidra --transport stdio
set "exit_code=%errorlevel%"
popd
exit /b %exit_code%

:failed
set "exit_code=%errorlevel%"
popd
exit /b %exit_code%

#!/bin/sh
set -eu

MCP_JAR="/opt/ghidra-mcp/server.jar"
if [ ! -f "$MCP_JAR" ]; then
  echo "Ghidra MCP jar not found: $MCP_JAR" >&2
  exit 1
fi

# Ghidra's distribution splits its runtime across module jars. The MCP release
# intentionally does not bundle them, so construct the classpath deterministically.
GHIDRA_CLASSPATH="$(find "$GHIDRA_HOME" -type f -name '*.jar' -print | LC_ALL=C sort | tr '\n' ':')"

export GHIDRA_MCP_FILE_ROOT="${GHIDRA_MCP_FILE_ROOT:-/workspace}"
export GHIDRA_MCP_ALLOW_SCRIPTS="${GHIDRA_MCP_ALLOW_SCRIPTS:-0}"
export GHIDRA_MCP_BIND_HOST="${GHIDRA_MCP_BIND_HOST:-127.0.0.1}"

exec java ${JAVA_OPTS:--Xmx4g -XX:+UseG1GC} \
  -Duser.home=/home/analyst \
  -cp "${MCP_JAR}:${GHIDRA_CLASSPATH}" \
  com.xebyte.headless.GhidraMCPHeadlessServer \
  --bind "${GHIDRA_MCP_BIND_HOST}" --port 8089

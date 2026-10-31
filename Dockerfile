ARG UBUNTU_VERSION=24.04
ARG JADX_VERSION=1.5.6
ARG GHIDRA_VERSION=12.1.4
ARG GHIDRA_SHA256=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
ARG GHIDRA_MCP_VERSION=7.0.0
ARG GHIDRA_MCP_SHA256=d133c4c869a0d9f605c1c9426bf5d9064772a6947ccecde0f42fbbffecf1d812
ARG GHIDRA_MCP_BRIDGE_SHA256=a75050061d0d1514d4b11e6288ea7575c09ab6125a1394c33fe349fb7658bbae
ARG FRIDA_TOOLS_VERSION=14.11.0
ARG APKTOOL_VERSION=3.0.3
ARG UBER_APK_SIGNER_VERSION=1.3.0
ARG CODEX_CLI_VERSION=0.162.1
ARG CLAUDE_CODE_VERSION=2.1.316
ARG NODE_VERSION=22.23.4
ARG ANDROID_PLATFORM_TOOLS_URL=https://dl.google.com/android/repository/platform-tools-latest-linux.zip

# Shared by the web control plane and durable assessment worker. This stage
# intentionally excludes Java, JADX, Apktool and Ghidra.
FROM ubuntu:${UBUNTU_VERSION} AS provider-runtime

ARG FRIDA_TOOLS_VERSION
ARG CODEX_CLI_VERSION
ARG CLAUDE_CODE_VERSION
ARG NODE_VERSION
ARG ANDROID_PLATFORM_TOOLS_URL

ENV DEBIAN_FRONTEND=noninteractive \
    ANDROID_HOME=/opt/android-sdk \
    PATH=/opt/android-sdk/platform-tools:${PATH} \
    DISABLE_AUTOUPDATER=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash bubblewrap ca-certificates curl file git jq openssh-client python3 python3-pip python3-venv tini unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
      amd64) node_arch=x64 ;; \
      arm64) node_arch=arm64 ;; \
      *) echo "Unsupported Node architecture" >&2; exit 1 ;; \
    esac; \
    node_archive="node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    curl -fL "https://nodejs.org/dist/v${NODE_VERSION}/${node_archive}" -o "/tmp/${node_archive}"; \
    curl -fL "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" -o /tmp/node-shasums.txt; \
    grep "  ${node_archive}$" /tmp/node-shasums.txt > /tmp/node-sha256.txt; \
    (cd /tmp && sha256sum -c node-sha256.txt); \
    tar -xJf "/tmp/${node_archive}" -C /usr/local --strip-components=1; \
    rm "/tmp/${node_archive}" /tmp/node-shasums.txt /tmp/node-sha256.txt; \
    python3 -m pip install --no-cache-dir --break-system-packages \
      "frida-tools==${FRIDA_TOOLS_VERSION}" "Flask==3.1.2" "gunicorn==23.0.0"; \
    npm install --global "@openai/codex@${CODEX_CLI_VERSION}" "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"; \
    node --version; \
    codex --version; \
    claude --version

RUN set -eux; \
    curl -fL "${ANDROID_PLATFORM_TOOLS_URL}" -o /tmp/platform-tools.zip; \
    mkdir -p /opt/android-sdk; \
    unzip -q /tmp/platform-tools.zip -d /opt/android-sdk; \
    rm /tmp/platform-tools.zip

RUN set -eux; \
    existing_user="$(getent passwd 1000 | cut -d: -f1)"; \
    existing_group="$(getent group 1000 | cut -d: -f1)"; \
    if [ -n "$existing_user" ]; then \
      usermod --login analyst --home /home/analyst --move-home "$existing_user"; \
      [ "$existing_group" = "analyst" ] || groupmod --new-name analyst "$existing_group"; \
    else \
      useradd --create-home --shell /bin/bash --uid 1000 analyst; \
    fi; \
    mkdir -p /workspace /home/analyst/.android /home/analyst/.codex /home/analyst/.claude; \
    chown -R analyst:analyst /workspace /home/analyst

WORKDIR /workspace
USER analyst

FROM provider-runtime AS web
CMD ["gunicorn", "--bind", "0.0.0.0:8787", "--workers", "1", "--threads", "8", "--timeout", "0", "ui.app:app"]

# The worker owns device execution and APK analysis. It reuses the provider
# runtime layers, then adds only the tools required by pipeline/pipeline.py.
FROM provider-runtime AS worker

ARG JADX_VERSION
ARG GHIDRA_MCP_VERSION
ARG GHIDRA_MCP_BRIDGE_SHA256
ARG APKTOOL_VERSION
ARG UBER_APK_SIGNER_VERSION

USER root
ENV JADX_HOME=/opt/jadx \
    PATH=/opt/jadx/bin:${PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-21-jre-headless \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip; \
    mkdir -p /opt/jadx; \
    unzip -q /tmp/jadx.zip -d /opt/jadx; \
    rm /tmp/jadx.zip; \
    curl -fL "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" -o /opt/apktool.jar; \
    printf '%s\n' '#!/bin/sh' 'exec java -jar /opt/apktool.jar "$@"' > /usr/local/bin/apktool; \
    chmod 0755 /usr/local/bin/apktool; \
    curl -fL "https://github.com/patrickfav/uber-apk-signer/releases/download/v${UBER_APK_SIGNER_VERSION}/uber-apk-signer-${UBER_APK_SIGNER_VERSION}.jar" -o /opt/uber-apk-signer.jar; \
    printf '%s\n' '#!/bin/sh' 'exec java -jar /opt/uber-apk-signer.jar "$@"' > /usr/local/bin/uber-apk-signer; \
    chmod 0755 /usr/local/bin/uber-apk-signer

RUN set -eux; \
    mkdir -p /opt/ghidra-mcp; \
    bridge_wheel="ghidra_mcp_bridge-${GHIDRA_MCP_VERSION}-py3-none-any.whl"; \
    curl -fL "https://github.com/bethington/ghidra-mcp/releases/download/v${GHIDRA_MCP_VERSION}/${bridge_wheel}" -o "/tmp/${bridge_wheel}"; \
    echo "${GHIDRA_MCP_BRIDGE_SHA256}  /tmp/${bridge_wheel}" | sha256sum -c -; \
    python3 -m venv /opt/ghidra-mcp/venv; \
    /opt/ghidra-mcp/venv/bin/pip install --no-cache-dir "/tmp/${bridge_wheel}"; \
    rm "/tmp/${bridge_wheel}"; \
    chown -R analyst:analyst /opt/ghidra-mcp

USER analyst
CMD ["python3", "-m", "ui.worker"]

# Full Ghidra is isolated in the native-analysis service and is not inherited
# by either the web or worker image.
FROM eclipse-temurin:21-jdk-noble AS reverse-engineering

ARG GHIDRA_VERSION
ARG GHIDRA_SHA256
ARG GHIDRA_MCP_VERSION
ARG GHIDRA_MCP_SHA256

ENV DEBIAN_FRONTEND=noninteractive \
    GHIDRA_HOME=/opt/ghidra \
    PATH=/opt/ghidra:/opt/ghidra/support:${PATH}

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates curl jq unzip \
    && rm -rf /var/lib/apt/lists/*

# The API lookup resolves Ghidra's release-date filename; the pinned tag and
# SHA-256 still make the downloaded archive reproducible.
RUN set -eux; \
    ghidra_url="$(curl -fsSL "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_${GHIDRA_VERSION}_build" \
      | jq -er '.assets[] | select(.name | test("^ghidra_[0-9].*\\.zip$")) | .browser_download_url')"; \
    curl --fail --location --retry 5 --retry-all-errors --retry-delay 2 "$ghidra_url" -o /tmp/ghidra.zip; \
    echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c -; \
    mkdir -p /opt/ghidra; \
    unzip -q /tmp/ghidra.zip -d /tmp/ghidra-extract; \
    mv /tmp/ghidra-extract/ghidra_*/* /opt/ghidra/; \
    rm -rf /tmp/ghidra.zip /tmp/ghidra-extract

RUN set -eux; \
    mkdir -p /opt/ghidra-mcp; \
    curl -fL "https://github.com/bethington/ghidra-mcp/releases/download/v${GHIDRA_MCP_VERSION}/GhidraMCP-${GHIDRA_MCP_VERSION}.zip" -o /tmp/ghidra-mcp.zip; \
    echo "${GHIDRA_MCP_SHA256}  /tmp/ghidra-mcp.zip" | sha256sum -c -; \
    unzip -q /tmp/ghidra-mcp.zip -d /opt/ghidra-mcp/extension; \
    ln -s "/opt/ghidra-mcp/extension/GhidraMCP/lib/GhidraMCP-${GHIDRA_MCP_VERSION}.jar" /opt/ghidra-mcp/server.jar; \
    rm /tmp/ghidra-mcp.zip

COPY scripts/ghidra-mcp-backend.sh /usr/local/bin/ghidra-mcp-backend
RUN set -eux; \
    chmod 0755 /usr/local/bin/ghidra-mcp-backend; \
    existing_user="$(getent passwd 1000 | cut -d: -f1)"; \
    existing_group="$(getent group 1000 | cut -d: -f1)"; \
    if [ -n "$existing_user" ]; then \
      usermod --login analyst --home /home/analyst --move-home "$existing_user"; \
      [ "$existing_group" = "analyst" ] || groupmod --new-name analyst "$existing_group"; \
    else \
      useradd --create-home --shell /bin/bash --uid 1000 analyst; \
    fi; \
    mkdir -p /workspace /home/analyst/.ghidra; \
    chown -R analyst:analyst /workspace /home/analyst

WORKDIR /workspace
USER analyst
CMD ["/usr/local/bin/ghidra-mcp-backend"]

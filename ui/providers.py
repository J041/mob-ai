from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import shutil
from typing import Any


PROVIDER_IDS = {"codex", "claude"}


def detect_usage_limit(output: str, *, now: datetime | None = None) -> dict[str, str] | None:
    """Recognize plan-usage exhaustion without conflating transient request throttling."""
    text = output or ""
    lowered = text.lower()
    markers = (
        "subscription_sharing_usage_limit_exceeded",
        "usage_limit_exceeded",
        "usage limit exceeded",
        "you've hit your usage limit",
        "you have hit your usage limit",
        "five-hour usage limit",
        "5-hour usage limit",
        "weekly usage limit",
    )
    marker = next((value for value in markers if value in lowered), "")
    if not marker:
        return None

    current = now or datetime.now(timezone.utc)
    reset_utc = ""
    iso_matches = re.findall(
        r"20\d{2}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})",
        text,
    )
    for value in reversed(iso_matches):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            reset_utc = parsed.astimezone(timezone.utc).isoformat()
            break
        except ValueError:
            pass
    if not reset_utc:
        duration = re.search(
            r"(?:try again|resets?|retry)\s+(?:after|in)\s+"
            r"(?:(\d+)\s*(?:hours?|hrs?|h))?\s*"
            r"(?:(\d+)\s*(?:minutes?|mins?|m))?\s*"
            r"(?:(\d+)\s*(?:seconds?|secs?|s))?",
            lowered,
        )
        if duration and any(duration.groups()):
            hours, minutes, seconds = (int(value or 0) for value in duration.groups())
            reset_utc = (current + timedelta(hours=hours, minutes=minutes, seconds=seconds)).isoformat()

    lines = [strip for line in text.splitlines() if (strip := line.strip())]
    detail = next((line for line in reversed(lines) if marker in line.lower()), "Usage allowance exhausted.")
    return {
        "code": "subscription_sharing_usage_limit_exceeded" if "subscription_sharing" in lowered else "usage_limit_exceeded",
        "detail": detail[:1000],
        "reset_utc": reset_utc,
    }


@dataclass(frozen=True)
class ProviderRequest:
    provider: str
    prompt: str
    cwd: Path
    schema_path: Path
    output_path: Path
    model: str = ""
    reasoning_effort: str = ""
    reasoning_mode: str = "single"
    writable: bool = False
    mcp_config: Path | None = None
    extra_args: tuple[str, ...] = ()


class ProviderAdapter:
    id = ""
    label = ""

    def available(self) -> bool:
        return bool(shutil.which(self.executable()))

    def executable(self) -> str:
        raise NotImplementedError

    def prepare(self, request: ProviderRequest) -> tuple[list[str], str]:
        raise NotImplementedError

    def finalize(self, request: ProviderRequest, exit_code: int, output: str) -> bool:
        return exit_code == 0 and request.output_path.is_file()


class CodexAdapter(ProviderAdapter):
    id = "codex"
    label = "Codex"

    def executable(self) -> str:
        return shutil.which("codex") or "codex"

    def prepare(self, request: ProviderRequest) -> tuple[list[str], str]:
        command = [
            self.executable(), "exec", "--sandbox", "workspace-write" if request.writable else "read-only",
            "--skip-git-repo-check",
            "--enable" if request.reasoning_mode == "parallel" else "--disable", "multi_agent",
            "--color", "never", "--config", 'approval_policy="never"',
        ]
        if request.reasoning_effort:
            command.extend(["--config", f"model_reasoning_effort={json.dumps(request.reasoning_effort)}"])
        command.extend(request.extra_args)
        command.extend(["--output-schema", str(request.schema_path), "--output-last-message", str(request.output_path)])
        if request.model:
            command.extend(["--model", request.model])
        command.append("-")
        return command, request.prompt


class ClaudeAdapter(ProviderAdapter):
    id = "claude"
    label = "Claude"

    def executable(self) -> str:
        return shutil.which("claude") or "claude"

    def prepare(self, request: ProviderRequest) -> tuple[list[str], str]:
        schema = json.loads(request.schema_path.read_text(encoding="utf-8"))
        prompt = (
            request.prompt
            + "\n\nYour final response must contain only one JSON object matching this schema exactly. "
            + "Do not wrap it in Markdown fences.\n"
            + json.dumps(schema, ensure_ascii=False)
        )
        if request.reasoning_effort:
            prompt += f"\nRequested reasoning effort: {request.reasoning_effort}."
        command = [self.executable(), "-p", "--output-format", "json", "--no-session-persistence"]
        if request.model:
            command.extend(["--model", request.model])
        if request.reasoning_effort:
            command.extend(["--effort", request.reasoning_effort])
        if request.writable:
            allowed = "Read,Edit,Write,Glob,Grep"
            if request.mcp_config:
                allowed += ",mcp__ghidra"
            if request.reasoning_mode == "parallel":
                allowed += ",Agent,Task"
            command.extend([
                "--permission-mode", "acceptEdits", "--allowedTools", allowed,
                "--disallowedTools", "Bash,WebFetch,WebSearch,NotebookEdit",
                "--max-turns", "24",
            ])
            if request.mcp_config:
                command.extend(["--mcp-config", str(request.mcp_config), "--strict-mcp-config"])
        else:
            command.extend([
                "--permission-mode", "plan", "--disallowedTools",
                "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch,Agent,Task", "--max-turns", "1",
            ])
        return command, prompt

    def finalize(self, request: ProviderRequest, exit_code: int, output: str) -> bool:
        if exit_code != 0:
            return False
        try:
            envelope = json.loads(output)
            content = envelope.get("result") if isinstance(envelope, dict) else ""
            if not isinstance(content, str):
                return False
            content = content.strip()
            fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", content, re.S | re.I)
            if fenced:
                content = fenced.group(1)
            value = json.loads(content)
            if not isinstance(value, dict):
                return False
            request.output_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            return True
        except (OSError, json.JSONDecodeError):
            return False


ADAPTERS: dict[str, ProviderAdapter] = {
    "codex": CodexAdapter(),
    "claude": ClaudeAdapter(),
}


def provider_adapter(provider: str) -> ProviderAdapter:
    try:
        return ADAPTERS[provider]
    except KeyError as error:
        raise ValueError(f"Unsupported reasoning provider: {provider}") from error


def validate_provider_output(path: Path, schema_path: Path) -> bool:
    """Validate the strict object schemas used by Mob-AI without another runtime dependency."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(value, dict):
        return False
    required = set(schema.get("required") or [])
    properties = schema.get("properties") or {}
    if not required.issubset(value) or (schema.get("additionalProperties") is False and set(value) - set(properties)):
        return False
    for key, rule in properties.items():
        if key not in value:
            continue
        item = value[key]
        expected = rule.get("type")
        if expected == "string" and not isinstance(item, str):
            return False
        if expected == "array" and not isinstance(item, list):
            return False
        if expected == "object" and not isinstance(item, dict):
            return False
        if expected == "integer" and (not isinstance(item, int) or isinstance(item, bool)):
            return False
        if rule.get("enum") and item not in rule["enum"]:
            return False
    return True


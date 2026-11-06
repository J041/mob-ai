"""Provider-reported token accounting for assessment reasoning calls."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from backend.providers import provider_token_usage


LEDGER_NAME = "provider-usage.jsonl"
_cache: dict[str, tuple[tuple[tuple[str, int, int], ...], dict[str, Any]]] = {}


def _provider_logs(run_dir: Path) -> list[Path]:
    result: list[Path] = []
    agent = run_dir / "agent"
    if not agent.is_dir():
        return result
    for path in agent.rglob("*.log"):
        if path.name not in {"codex.log", "claude.log"}:
            continue
        relative = path.relative_to(agent)
        # Diagnostic/recovery snapshots copy earlier logs and must not count twice.
        if any(part in {"before", "after"} for part in relative.parts):
            continue
        result.append(path)
    return sorted(result)


def _legacy_entries(run_dir: Path, *, exclude: Path | None = None) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    excluded = exclude.resolve() if exclude else None
    for path in _provider_logs(run_dir):
        if excluded is not None and path.resolve() == excluded:
            continue
        provider = "claude" if path.name == "claude.log" else "codex"
        try:
            usage = provider_token_usage(provider, path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        if not usage:
            continue
        relative = path.relative_to(run_dir).as_posix()
        entries.append({
            "call_id": f"legacy:{relative}", "phase": "historical",
            "artifact": relative, "model": "", "created_utc": "", **usage,
        })
    return entries


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries = []
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("call_id"):
            entries.append(value)
    return entries


def _write_ledger(path: Path, entries: list[dict[str, Any]]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(
            "".join(json.dumps(item, separators=(",", ":"), ensure_ascii=False) + "\n" for item in entries),
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def record_provider_usage(
    run_dir: Path, usage: dict[str, Any] | None, *, phase: str,
    artifact: Path, model: str = "",
) -> None:
    if not usage or int(usage.get("total_tokens") or 0) <= 0:
        return
    ledger = run_dir / LEDGER_NAME
    relative = artifact.resolve().relative_to(run_dir.resolve()).as_posix()
    entries = _read_ledger(ledger) if ledger.is_file() else _legacy_entries(run_dir, exclude=artifact)
    call_id = f"provider:{relative}"
    if any(item.get("call_id") == call_id for item in entries):
        return
    entries.append({
        "call_id": call_id,
        "phase": phase,
        "artifact": relative,
        "model": model,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        **usage,
    })
    _write_ledger(ledger, entries)
    _cache.pop(str(run_dir.resolve()), None)


def aggregate_token_usage(entries: list[dict[str, Any]]) -> dict[str, Any]:
    numeric_fields = (
        "input_tokens", "cached_input_tokens", "cache_creation_input_tokens",
        "output_tokens", "reasoning_output_tokens", "total_tokens",
    )
    result: dict[str, Any] = {field: 0 for field in numeric_fields}
    by_provider: dict[str, int] = {}
    detailed_calls = 0
    for entry in entries:
        for field in numeric_fields:
            result[field] += int(entry.get(field) or 0)
        provider = str(entry.get("provider") or "unknown")
        by_provider[provider] = by_provider.get(provider, 0) + int(entry.get("total_tokens") or 0)
        detailed_calls += int(bool(entry.get("detail_available")))
    result.update({
        "calls": len(entries),
        "detailed_calls": detailed_calls,
        "total_only_calls": len(entries) - detailed_calls,
        "by_provider": by_provider,
        "complete": bool(entries) and detailed_calls == len(entries),
    })
    return result


def assessment_token_usage(run_dir: Path) -> dict[str, Any]:
    ledger = run_dir / LEDGER_NAME
    files = [ledger] if ledger.is_file() else _provider_logs(run_dir)
    signature = tuple(
        (str(path), path.stat().st_mtime_ns, path.stat().st_size)
        for path in files if path.is_file()
    )
    key = str(run_dir.resolve())
    cached = _cache.get(key)
    if cached and cached[0] == signature:
        return dict(cached[1])
    entries = _read_ledger(ledger) if ledger.is_file() else _legacy_entries(run_dir)
    usage = aggregate_token_usage(entries)
    _cache[key] = (signature, usage)
    return dict(usage)


def token_usage_delta(after: dict[str, Any], before: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "input_tokens", "cached_input_tokens", "cache_creation_input_tokens",
        "output_tokens", "reasoning_output_tokens", "total_tokens", "calls",
        "detailed_calls", "total_only_calls",
    )
    result = {field: max(0, int(after.get(field) or 0) - int(before.get(field) or 0)) for field in fields}
    result["complete"] = result["calls"] > 0 and result["detailed_calls"] == result["calls"]
    return result

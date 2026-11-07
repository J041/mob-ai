"""Typed HTTP request payloads used by the Flask boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class RequestPayload:
    """Immutable mapping wrapper with normalized fields shared by run requests."""

    authorized: bool
    provider: str
    model: str
    reasoning_effort: str
    reasoning_mode: str
    raw: Mapping[str, Any] = field(repr=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "RequestPayload":
        body = dict(value or {})
        return cls(
            authorized=bool(body.get("authorized")),
            provider=str(body.get("provider") or "codex"),
            model=str(body.get("model") or ""),
            reasoning_effort=str(body.get("reasoning_effort") or ""),
            reasoning_mode=str(body.get("reasoning_mode") or "single"),
            raw=body,
        )

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)


@dataclass(frozen=True)
class StartAssessmentRequest(RequestPayload):
    """Typed marker for a new or linked assessment request."""


@dataclass(frozen=True)
class ContinuationRequest(RequestPayload):
    """Typed marker for resume and diagnostic retry requests."""


@dataclass(frozen=True)
class DeviceReadinessRequest:
    transport: str
    target: str
    frida_server: str
    frida_version: str
    start_frida: bool
    authorized: bool


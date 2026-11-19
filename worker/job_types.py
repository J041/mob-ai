"""Single registry for durable job execution and presentation semantics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class JobType:
    name: str
    executor: str
    label: str
    description: str
    requires_provider: bool
    counts_as_attempt: bool
    supports_pause: bool
    successful_statuses: frozenset[str]
    default_attempt_kind: str
    control_noun: str = "assessment"
    sequence_noun: str = "Attempt"
    history_noun: str = "attempt"
    attempt_labels: tuple[tuple[str, str], ...] = ()

    def is_success(self, status: str) -> bool:
        return status in self.successful_statuses

    def attempt_label(self, attempt_kind: str) -> str:
        labels = dict(self.attempt_labels)
        return labels.get(attempt_kind, self.label)

    def public_dict(self) -> dict[str, Any]:
        """Return only stable UI-safe behavior; executor bindings remain private."""
        return {
            "name": self.name,
            "label": self.label,
            "description": self.description,
            "requires_provider": self.requires_provider,
            "counts_as_attempt": self.counts_as_attempt,
            "supports_pause": self.supports_pause,
            "successful_statuses": sorted(self.successful_statuses),
            "default_attempt_kind": self.default_attempt_kind,
            "control_noun": self.control_noun,
            "sequence_noun": self.sequence_noun,
            "history_noun": self.history_noun,
            "attempt_labels": dict(self.attempt_labels),
        }


JOB_TYPES: dict[str, JobType] = {
    "start": JobType(
        name="start", executor="loop.new", label="Assessment",
        description="Start a new authorized APK assessment.",
        requires_provider=True, counts_as_attempt=True, supports_pause=True,
        successful_statuses=frozenset({"success", "success_without_bypass"}),
        default_attempt_kind="initial",
        attempt_labels=(("initial", "Initial assessment"),),
    ),
    "resume": JobType(
        name="resume", executor="loop.resume", label="Continue assessment",
        description="Continue a recoverable or iteration-limited assessment checkpoint.",
        requires_provider=True, counts_as_attempt=True, supports_pause=True,
        successful_statuses=frozenset({"success", "success_without_bypass"}),
        default_attempt_kind="resume",
        attempt_labels=(
            ("resume", "Resume iterations"),
            ("frida_recovery", "Fix Frida"),
            ("observation_recovery", "Recover observation"),
            ("validation_recovery", "Recover validation"),
            ("checkpoint_recovery", "Recover checkpoint"),
            ("native_selection_recovery", "Recover native selection"),
            ("provider_recovery", "Recover provider decision"),
            ("native_replenishment_recovery", "Recover native replenishment"),
            ("usage_limit_resume", "Resume after usage reset"),
            ("pause_resume", "Continue after pause"),
        ),
    ),
    "retry": JobType(
        name="retry", executor="loop.retry_with_diagnostics", label="Rerun / retry",
        description="Rerun observation with diagnostics and continue from preserved evidence.",
        requires_provider=True, counts_as_attempt=True, supports_pause=True,
        successful_statuses=frozenset({"success", "success_without_bypass"}),
        default_attempt_kind="diagnostic_retry",
        attempt_labels=(("diagnostic_retry", "Rerun / retry"),),
    ),
    "deep_goal": JobType(
        name="deep_goal", executor="function.deep_goal", label="Deep investigation",
        description="Run an optional read-only, token-bounded investigation of recorded evidence.",
        requires_provider=True, counts_as_attempt=False, supports_pause=False,
        successful_statuses=frozenset({"investigation_complete"}),
        default_attempt_kind="deep_investigation", control_noun="investigation",
        sequence_noun="Deep investigation", history_noun="investigation",
        attempt_labels=(("deep_investigation", "Deep investigation"),),
    ),
    "launch_bypass": JobType(
        name="launch_bypass", executor="function.launch_bypass", label="Run APK + bypass",
        description="Launch a validated Frida bypass as an operator-controlled session.",
        requires_provider=False, counts_as_attempt=False, supports_pause=False,
        successful_statuses=frozenset({"bypass_session_ended"}),
        default_attempt_kind="bypass_session", control_noun="session",
        sequence_noun="Bypass session", history_noun="bypass session",
        attempt_labels=(("bypass_session", "Run APK + bypass"),),
    ),
}


def job_type(name: str) -> JobType:
    try:
        return JOB_TYPES[name]
    except KeyError as error:
        raise ValueError(f"Unsupported queued job kind: {name!r}.") from error


def public_job_type_catalog() -> dict[str, dict[str, Any]]:
    return {name: spec.public_dict() for name, spec in JOB_TYPES.items()}

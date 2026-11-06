"""Actionable terminal-outcome classification for assessment runs."""

from __future__ import annotations

import json
from typing import Any

from pipeline.diagnostic_recipes import DIAGNOSTIC_MAX_ROUNDS


def terminal_outcome(summary: dict[str, Any] | None) -> dict[str, Any]:
    """Turn a coarse terminal status into a stable, operator-actionable outcome.

    The classifier intentionally uses only persisted assessment evidence. It is
    also called by the web API so older runs receive the same presentation
    without rewriting their audit log.
    """
    summary = summary or {}
    status = str(summary.get("status") or "").strip().lower()
    if status not in {
        "human_review", "assessment_failed", "environment_error", "provider_error",
        "codex_error", "codex_boundary_error", "pipeline_error", "worker_error",
        "usage_limited", "paused", "cancelled", "max_iterations", "needs_input", "error", "failed",
    }:
        return {}

    iterations = [item for item in (summary.get("iterations") or []) if isinstance(item, dict)]
    last = iterations[-1] if iterations else {}
    codex = last.get("codex") if isinstance(last.get("codex"), dict) else {}
    evidence = json.dumps({
        "detail": summary.get("detail"),
        "reason": summary.get("reason"),
        "codex": codex,
    }, ensure_ascii=False).lower()
    diagnostic_rounds = sum(1 for item in iterations if isinstance(item.get("diagnostics"), dict))
    diagnostic_remaining = max(0, DIAGNOSTIC_MAX_ROUNDS - diagnostic_rounds)

    def outcome(
        code: str, label: str, explanation: str, recommended_action: str,
        action: str, *, severity: str = "error",
    ) -> dict[str, Any]:
        return {
            "code": code,
            "label": label,
            "explanation": explanation,
            "recommended_action": recommended_action,
            "action": action,
            "severity": severity,
            "diagnostics": {
                "used": diagnostic_rounds,
                "limit": DIAGNOSTIC_MAX_ROUNDS,
                "remaining": diagnostic_remaining,
            },
        }

    detail = str(summary.get("detail") or "The assessment stopped without a more specific explanation.")
    reason = str(summary.get("reason") or "")
    checkpoint = summary.get("checkpoint") if isinstance(summary.get("checkpoint"), dict) else {}

    if status == "usage_limited":
        return outcome(
            "provider_usage_limited", "Provider usage limit reached", detail,
            "Wait for the recorded account reset, or select another authenticated provider, then resume from the saved checkpoint.",
            "resume_after_reset", severity="warning",
        )
    if status == "paused":
        return outcome(
            "operator_paused", "Paused by operator", detail,
            "Continue from the saved safe-stage checkpoint when the device and provider are ready.",
            "continue_checkpoint", severity="warning",
        )
    if status == "cancelled":
        return outcome(
            "operator_cancelled", "Cancelled by operator", detail,
            "Review the preserved evidence. Start a new attempt only if further assessment is required.",
            "review_evidence", severity="warning",
        )
    if status in {"provider_error", "codex_error"}:
        return outcome(
            "reasoning_provider_failed", "Reasoning provider failed", detail,
            "Check provider authentication and its log, then rerun; completed static and native analysis will be reused.",
            "retry_provider",
        )
    if status == "codex_boundary_error":
        return outcome(
            "provider_boundary_violation", "Provider crossed the write boundary", detail,
            "Inspect the provider decision and log. Retry only after confirming the candidate-only write boundary remains intact.",
            "review_provider_output",
        )
    if status in {"environment_error", "pipeline_error", "worker_error", "error", "failed"}:
        stage = str(checkpoint.get("stage") or "")
        if reason == "adaptive_diagnostics_failure":
            return outcome(
                "diagnostic_execution_failed", "Runtime diagnostics failed", detail,
                "Verify the selected device, root/SELinux access, and Frida readiness, then rerun the failed diagnostic checkpoint.",
                "retry_diagnostics",
            )
        action = "recover_checkpoint" if stage else "run_device_readiness"
        stage_text = f" during {stage}" if stage else ""
        return outcome(
            "device_or_tool_unavailable", "Device or tool unavailable",
            f"An operational dependency failed{stage_text}. {detail}",
            "Reconnect the exact target, run Device readiness, and recover the checkpoint or rerun the assessment.",
            action,
        )
    if status == "max_iterations":
        return outcome(
            "iteration_budget_reached", "Iteration budget reached", detail,
            "Review the last validation delta, then continue with a bounded number of additional iterations if the evidence supports it.",
            "continue_iterations", severity="warning",
        )
    if status == "assessment_failed":
        if reason == "no_progress":
            return outcome(
                "no_progress", "No progress between validations", detail,
                "Compare the last two attempts and change the evidence strategy, target setup, or success policy before rerunning.",
                "compare_attempts",
            )
        if reason == "no_justified_change":
            return outcome(
                "no_justified_change", "No evidence-supported hook remains", detail,
                "Collect stronger runtime evidence or review the current artifacts; repeating the same candidate is unlikely to help.",
                "review_evidence",
            )
        return outcome(
            "success_policy_not_met", "Success policy was not met", detail,
            "Open the failed success checks and attempt comparison, then rerun only with a targeted evidence or hook change.",
            "review_policy_checks",
        )

    if "remote attestation" in evidence or "server-side attestation" in evidence:
        return outcome(
            "possible_remote_attestation", "Possible remote attestation", detail,
            "Review the attestation evidence and authorization scope. A local Frida hook may not be sufficient or appropriate.",
            "manual_scope_review",
        )
    if diagnostic_rounds >= DIAGNOSTIC_MAX_ROUNDS and any(marker in evidence for marker in (
        "diagnostic round", "diagnostic allowance", "diagnostics are exhausted", "both bounded",
    )):
        return outcome(
            "diagnostic_budget_exhausted", "Diagnostic budget exhausted", detail,
            "Review the collected diagnostic artifacts and choose a different evidence strategy before starting another reassessment.",
            "review_diagnostics",
        )
    if any(marker in evidence for marker in (
        "hidden runtime payload", "runtime-unpacked payload", "payload-dump", "payload dump",
        "unpacked image", "produced no artifacts",
    )):
        if diagnostic_remaining:
            recommendation = (
                f"Rerun and let the provider use the {diagnostic_remaining} remaining diagnostic round"
                f"{'s' if diagnostic_remaining != 1 else ''} for late-attach, dynamic-loading, or bounded payload evidence."
            )
            action = "retry_diagnostics"
        else:
            recommendation = "Review the loader and captured artifacts; further automated payload capture requires a new scoped reassessment."
            action = "review_native_evidence"
        return outcome(
            "protected_payload_unavailable", "Protected runtime payload unavailable", detail,
            recommendation, action,
        )
    if any(marker in evidence for marker in (
        "instrumentation perturb", "instrumentation changed", "changed behavior", "invalid version",
        "jni_onload returning", "jni_onload behavior",
    )):
        return outcome(
            "instrumentation_changed_behavior", "Instrumentation changed app behavior", detail,
            "Retry with an isolated late-attach or launch-comparison recipe before adding broader hooks.",
            "retry_late_attach",
        )
    if any(marker in evidence for marker in (
        "speculative", "overly broad", "no exact detector", "no specific executed detector",
        "insufficient evidence", "no narrow candidate", "no justified",
    )):
        return outcome(
            "insufficient_causal_evidence", "Insufficient causal evidence", detail,
            "Inspect the cited evidence and rerun with a targeted unused diagnostic recipe; do not broaden the bypass without a confirmed detector.",
            "collect_targeted_evidence",
        )
    return outcome(
        "manual_review_required", "Manual review required", detail,
        "Open the cited artifacts and latest provider decision, then choose whether to rerun, adjust the policy, or stop.",
        "review_evidence",
    )


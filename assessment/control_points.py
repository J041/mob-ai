from __future__ import annotations

from typing import Any


# Ordered from the evidence source to the user-visible or process-level effect.
# These stages are intentionally framework- and application-agnostic.
CONTROL_POINT_STAGES = (
    "detector_inputs",
    "detector_methods",
    "decision_points",
    "enforcement_sinks",
    "termination_paths",
)

CONTROL_POINT_STATUSES = (
    "unexplored",
    "candidate",
    "tested",
    "blocked",
    "not_applicable",
)

HOOK_LAYERS = ("none", "java", "native", "mixed")


def control_point_prompt() -> str:
    return """Control-point coverage (general requirement):
- Reconstruct the app-owned path from detection evidence to its effect. Assess all five stages: detector_inputs, detector_methods, decision_points, enforcement_sinks, and termination_paths.
- A detector input is evidence consumed by a check; a detector method computes a detection result; a decision point branches or aggregates that result; an enforcement sink displays, blocks, redirects, or otherwise applies it; a termination path exits, crashes, or kills the process.
- Prefer an exact app-owned method or call site over a framework-wide or libc-wide hook. A narrowly conditioned enforcement-sink hook is eligible when the recorded success policy is about removing that exact warning or blocking effect. Preserve unrelated warnings and behavior.
- Failure or missing telemetry from one Java hook does not prove that every Java control point is unavailable. Assess a different app-owned decision, sink, or termination point before escalating to broad native interception.
- Never replace a method and then call the replacement through `this.sameMethod(...)`; preserve the overload handle and use `overload.call(this, ...)` when original behavior must continue.
- Return exactly one control_point_coverage entry for every stage. Cite concrete JADX, runtime, Ghidra, or prior-validation evidence. Use candidate for the stage changed in candidate.js, tested only for a previously validated approach, blocked only with specific evidence, and unexplored when it has genuinely not been assessed.
- Before returning human_review, no stage may remain unexplored or candidate. Before proposing a native or mixed hook, decision_points, enforcement_sinks, and termination_paths must each be assessed as candidate, tested, blocked, or not_applicable.
"""


def validate_control_point_decision(decision: dict[str, Any]) -> list[str]:
    """Apply semantic checks that the provider JSON schema cannot express safely."""
    errors: list[str] = []
    coverage = decision.get("control_point_coverage")
    if not isinstance(coverage, list):
        return ["control_point_coverage must be an array"]

    by_stage: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(coverage, 1):
        if not isinstance(item, dict):
            errors.append(f"control-point entry {index} must be an object")
            continue
        stage = item.get("stage")
        status = item.get("status")
        evidence = item.get("evidence")
        next_step = item.get("next_step")
        if stage not in CONTROL_POINT_STAGES:
            errors.append(f"control-point entry {index} has an invalid stage")
            continue
        if stage in by_stage:
            errors.append(f"control-point stage {stage} is duplicated")
        by_stage[stage] = item
        if status not in CONTROL_POINT_STATUSES:
            errors.append(f"control-point stage {stage} has an invalid status")
        if not isinstance(evidence, str) or not evidence.strip():
            errors.append(f"control-point stage {stage} requires concrete evidence")
        if not isinstance(next_step, str):
            errors.append(f"control-point stage {stage} requires a next_step string")
        elif status in {"candidate", "unexplored"} and not next_step.strip():
            errors.append(f"control-point stage {stage} requires a next step while {status}")

    missing = [stage for stage in CONTROL_POINT_STAGES if stage not in by_stage]
    if missing:
        errors.append("missing control-point stages: " + ", ".join(missing))
    if len(coverage) != len(CONTROL_POINT_STAGES):
        errors.append(f"control_point_coverage must contain exactly {len(CONTROL_POINT_STAGES)} entries")

    layer = decision.get("hook_layer")
    if layer not in HOOK_LAYERS:
        errors.append("hook_layer is invalid")

    outcome = decision.get("decision")
    if outcome == "human_review":
        unfinished = [
            stage for stage, item in by_stage.items()
            if item.get("status") in {"unexplored", "candidate"}
        ]
        if unfinished:
            errors.append("human_review cannot leave control points unfinished: " + ", ".join(unfinished))

    if outcome == "updated" and layer in {"native", "mixed"}:
        skipped = [
            stage for stage in ("decision_points", "enforcement_sinks", "termination_paths")
            if stage not in by_stage or by_stage[stage].get("status") == "unexplored"
        ]
        if skipped:
            errors.append("native escalation requires downstream control-point assessment: " + ", ".join(skipped))

    if outcome == "updated" and not any(
        item.get("status") == "candidate" for item in by_stage.values()
    ):
        errors.append("an updated candidate must identify at least one candidate control point")

    return errors

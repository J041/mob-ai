"""Provider prompt construction for bounded assessment iterations."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.diagnostic_recipes import (
    DIAGNOSTIC_MAX_ACTIONS_PER_PASS, DIAGNOSTIC_MAX_ROUNDS, diagnostic_recipe_prompt,
)
from assessment.control_points import control_point_prompt
from assessment.runtime import container_path, read_json


def build_iteration_prompt(
    run_dir: Path, candidate: Path, prior_dir: Path | None,
    iteration: int, start_iteration: int, end_iteration: int, *,
    reasoning_mode: str, specialist_count: int,
) -> str:
    selection_path = run_dir / "native-selection.json"
    selection = read_json(selection_path) if selection_path.is_file() else {"selected": []}
    selected_targets = selection.get("selected") or []
    batches = selection.get("batches") or []
    current_batch = int((batches[-1].get("number") if batches else 0) or 0)
    queued_count = len(selection.get("queue") or [])
    preparation_path = run_dir / "ghidra" / "preparation" / f"batch-{current_batch}.json"
    preparation = read_json(preparation_path) if preparation_path.is_file() else {}
    prepared_programs = [
        f"{item.get('program')} ({item.get('status')}, {item.get('function_count', '?')} functions)"
        for item in (preparation.get("programs") or []) if isinstance(item, dict)
    ]
    queue_context = (
        f"Native analysis queue batch {current_batch}; {queued_count} logical libraries remain queued. "
        "Only the active batch below is authorized for this iteration."
    )
    if selected_targets:
        rendered: list[str] = []
        for item in selected_targets:
            if not isinstance(item, dict):
                continue
            primary = item.get("primary") if isinstance(item.get("primary"), dict) else item
            rendered.append(f"- {primary.get('extracted')} [{item.get('priority')}]: {item.get('reason')}")
            cross = item.get("cross_abi")
            if isinstance(cross, dict):
                for variant in cross.get("variants") or []:
                    if isinstance(variant, dict):
                        rendered.append(f"  comparison: {variant.get('extracted')} ({cross.get('reason')})")
        rendered_targets = "\n".join(rendered)
        native_guidance = f"""{queue_context}
Codex/provider native triage selected these exact targets:
{rendered_targets}
The deterministic orchestrator prepared them before this reasoning step. Preparation manifest: {preparation_path}
Preparation status: {preparation.get('status', 'missing')}; Ghidra programs: {json.dumps(prepared_programs)}
Every complete program above is already imported, analyzed, open, and marked mcp_ready by trusted orchestration. Inspect each one with approval-free, read-only Ghidra MCP tools before concluding this iteration, always passing its exact program name, and cite the preparation manifest and inspected paths in evidence_used. Do not call connect_instance, import_file, open_program, load_tool_group, or any other approval-gated or state-changing MCP tool. If a target is recorded as partial or failed, report that limitation. Do not patch a binary."""
    else:
        native_guidance = f"{queue_context} Native triage selected no Ghidra targets. Do not infer a native detector from raw string matches alone."
    if reasoning_mode == "parallel":
        delegation = f"""Parallel specialist mode is enabled. Spawn no more than {specialist_count} read-only subagents for independent evidence review, then wait for them and synthesize their findings before deciding:
- static specialist: JADX Java/Kotlin detector evidence;
- runtime specialist: observations, Frida output, logcat, and success-check failures;
- native specialist when native evidence exists: suspicious libraries through read-only Ghidra MCP.
With only two useful scopes, do not create an unnecessary third specialist. Subagents must not edit candidate.js or any other file, run device tools, or claim success. The root agent is the only writer and remains responsible for the final structured decision."""
    else:
        delegation = "Single-agent mode is enabled. Do not spawn subagents; inspect and decide within this root session."
    recipe_guidance = diagnostic_recipe_prompt()
    control_point_guidance = control_point_prompt()
    return f"""You are the reasoning step in an explicitly authorized Android application assessment loop.

Iteration: {iteration} (this invocation covers {start_iteration} through {end_iteration})
Read-only run evidence directory: {run_dir}
Editable candidate hook: {candidate}
Previous iteration evidence: {prior_dir or 'none'}
Ghidra MCP container path prefix for this run: {container_path(run_dir)}
Native target selection: {container_path(selection_path)}

{delegation}

{native_guidance}

Goal: make the smallest evidence-based change to the candidate Frida hook that can satisfy the success policy. Inspect report.json, observations.json, adaptive-plan.json, JADX output, and prior Frida/logcat/validation records. If native evidence is relevant, use read-only Ghidra MCP tools for native libraries from this run.

{control_point_guidance}

Adaptive evidence escalation:
- When existing evidence is insufficient for a narrow candidate but a bounded runtime diagnostic could resolve the uncertainty, return decision `diagnostics` instead of `human_review`.
- Include one to {DIAGNOSTIC_MAX_ACTIONS_PER_PASS} unique `diagnostic_actions` selected only from this registry:
{recipe_guidance}
- `diagnostic_actions` is required in every structured response. Return an empty array for updated, no_change, and human_review decisions.
- Prefer compare_launch_modes and a single isolated trace before invasive capture. Use late_attach_observer when spawn instrumentation changes loader behavior. Request memory/DEX dumps or extract_embedded_payload only when evidence indicates dynamically loaded code; the worker scopes capture to the selected package and enforces the registry's shared artifact limits.
- The deterministic orchestrator executes diagnostics on the exact recorded device and makes the manifest available under diagnostics/pass-*/manifest.json for the next iteration. Do not edit candidate.js when requesting diagnostics.
- At most {DIAGNOSTIC_MAX_ROUNDS} diagnostic rounds are available, and completed actions cannot be requested again.

Hard boundaries:
- Edit only {candidate}. Do not modify the APK, pipeline, policy, reports, logs, or another file.
- Do not run ADB, Frida, the pipeline, install commands, or interact with a device. Deterministic orchestration performs validation.
- Do not rebuild or resign the APK.
- Keep hooks narrowly tied to observed anti-root, anti-debugging, or anti-hooking behavior. Do not disable unrelated controls.
- If evidence is insufficient and no remaining allowlisted diagnostic can resolve it, the next change is speculative/high-risk, or success requires remote-attestation defeat, return human_review without editing.
- Never claim success; only the structured policy establishes it.

Return the required structured decision after inspecting and, when justified, editing the candidate.
"""

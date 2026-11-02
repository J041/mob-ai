"""Single source of truth for bounded adaptive diagnostic recipes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Literal, Mapping


Invasiveness = Literal["low", "moderate", "high"]


@dataclass(frozen=True)
class ArtifactLimits:
    max_artifacts: int
    max_artifact_bytes: int
    max_total_bytes: int
    scope: str = "shared_pass"


@dataclass(frozen=True)
class DiagnosticRecipe:
    name: str
    invasiveness: Invasiveness
    prerequisites: tuple[str, ...]
    artifact_limits: ArtifactLimits
    ui_description: str

    def public_dict(self) -> dict[str, object]:
        return asdict(self)


NO_ARTIFACTS = ArtifactLimits(0, 0, 0)
BOUNDED_CAPTURE = ArtifactLimits(
    max_artifacts=5,
    max_artifact_bytes=1024 * 1024,
    max_total_bytes=5 * 1024 * 1024,
)
DIAGNOSTIC_MAX_ACTIONS_PER_PASS = 3
DIAGNOSTIC_MAX_ROUNDS = 2


_RECIPES = (
    DiagnosticRecipe(
        "trace_jni_registration", "low", ("frida", "spawn"), NO_ARTIFACTS,
        "Trace RegisterNatives calls to identify dynamically registered JNI methods and their native addresses.",
    ),
    DiagnosticRecipe(
        "capture_native_exceptions", "low", ("frida", "spawn"), NO_ARTIFACTS,
        "Capture native exception and crash context without changing return values.",
    ),
    DiagnosticRecipe(
        "trace_termination_calls", "low", ("frida", "spawn"), NO_ARTIFACTS,
        "Trace exit, abort, kill, and related termination calls to identify the component stopping the app.",
    ),
    DiagnosticRecipe(
        "inventory_executable_mappings", "low", ("frida", "spawn"), NO_ARTIFACTS,
        "Inventory executable modules and anonymous mappings visible from the instrumented process.",
    ),
    DiagnosticRecipe(
        "dump_runtime_payloads", "high", ("frida", "spawn", "runtime_memory_read"), BOUNDED_CAPTURE,
        "Capture bounded in-memory payloads that acquire executable permissions during startup.",
    ),
    DiagnosticRecipe(
        "compare_launch_modes", "moderate", ("adb", "frida", "restart_app"), NO_ARTIFACTS,
        "Compare clean launch, empty Frida spawn, and late attach to detect instrumentation-sensitive behavior.",
    ),
    DiagnosticRecipe(
        "late_attach_observer", "low", ("adb", "frida", "live_process"), NO_ARTIFACTS,
        "Launch normally and attach the observation agent afterward to reduce protected-loader perturbation.",
    ),
    DiagnosticRecipe(
        "snapshot_process_mappings", "moderate", ("adb", "root", "procfs", "restart_app"), NO_ARTIFACTS,
        "Snapshot new executable process mappings through rooted procfs access.",
    ),
    DiagnosticRecipe(
        "dump_new_executable_regions", "high", ("adb", "root", "procfs", "process_memory_read", "restart_app"), BOUNDED_CAPTURE,
        "Capture bounded anonymous, memfd, or deleted executable regions discovered after launch.",
    ),
    DiagnosticRecipe(
        "trace_dynamic_loading", "low", ("frida", "spawn"), NO_ARTIFACTS,
        "Trace dlopen, android_dlopen_ext, and dlsym activity to identify dynamically loaded protection code.",
    ),
    DiagnosticRecipe(
        "trace_signal_handlers", "moderate", ("frida", "spawn"), NO_ARTIFACTS,
        "Trace signal and sigaction registrations that may implement crash guards or anti-instrumentation behavior.",
    ),
    DiagnosticRecipe(
        "capture_runtime_dex", "high", ("frida", "spawn", "runtime_memory_read"), BOUNDED_CAPTURE,
        "Capture bounded DEX or compact-DEX images discovered in readable runtime mappings.",
    ),
    DiagnosticRecipe(
        "extract_embedded_payload", "moderate", ("selected_native_binaries",), BOUNDED_CAPTURE,
        "Carve bounded plaintext ELF, DEX, or compact-DEX payloads embedded in selected native libraries.",
    ),
)

DIAGNOSTIC_RECIPES: Mapping[str, DiagnosticRecipe] = MappingProxyType(
    {recipe.name: recipe for recipe in _RECIPES}
)
if len(DIAGNOSTIC_RECIPES) != len(_RECIPES):
    raise RuntimeError("Diagnostic recipe names must be unique")

DIAGNOSTIC_ACTIONS = frozenset(DIAGNOSTIC_RECIPES)


def diagnostic_recipe_catalog() -> list[dict[str, object]]:
    """Return JSON-safe recipe metadata in stable registry order."""
    return [recipe.public_dict() for recipe in DIAGNOSTIC_RECIPES.values()]


def diagnostic_recipe_prompt() -> str:
    """Render the allowlist and decision metadata for a reasoning provider."""
    lines = []
    for recipe in DIAGNOSTIC_RECIPES.values():
        requirements = ", ".join(recipe.prerequisites) or "none"
        limits = recipe.artifact_limits
        capture = (
            f"; shared capture cap {limits.max_artifacts} artifacts / "
            f"{limits.max_artifact_bytes} bytes each / {limits.max_total_bytes} bytes total"
            if limits.max_artifacts else "; no binary artifacts"
        )
        lines.append(
            f"  - {recipe.name} [{recipe.invasiveness}; requires {requirements}{capture}]: "
            f"{recipe.ui_description}"
        )
    return "\n".join(lines)

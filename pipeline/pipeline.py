#!/usr/bin/env python3
"""Authorized, auditable APK root/hooking assessment pipeline."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile

try:
    from pipeline.diagnostic_recipes import (
        BOUNDED_CAPTURE, DIAGNOSTIC_ACTIONS, DIAGNOSTIC_MAX_ACTIONS_PER_PASS,
        DIAGNOSTIC_RECIPES,
    )
    from pipeline.frida_runtimes import activate_frida_runtime
except ModuleNotFoundError:  # Direct execution from /workspace/pipeline.
    from diagnostic_recipes import (  # type: ignore
        BOUNDED_CAPTURE, DIAGNOSTIC_ACTIONS, DIAGNOSTIC_MAX_ACTIONS_PER_PASS,
        DIAGNOSTIC_RECIPES,
    )
    from frida_runtimes import activate_frida_runtime  # type: ignore

PATTERNS = {
    "root_framework": re.compile(r"RootBeer|Magisk|SuperSU|rooted|isRooted", re.I),
    "root_binary": re.compile(r"(/system/(?:x?bin)/su|/sbin/su|which\s+su)", re.I),
    "root_property": re.compile(r"ro\.(?:debuggable|secure)|test-keys|release-keys", re.I),
    "hook_framework": re.compile(r"frida|xposed|substrate|gum-js-loop|linjector", re.I),
    "debugger": re.compile(r"isDebuggerConnected|TracerPid|ptrace", re.I),
}
FRIDA_SHUTDOWN_GRACE_SECONDS = 10

DEFAULT_MODULES = {
    "java-files", "debugger", "properties", "rootbeer", "packages", "commands",
    "native-files", "native-antidebug", "anti-frida",
}
MODULE_MIN_LEVEL = {
    "java-files": 1, "debugger": 1, "properties": 1, "rootbeer": 1,
    "packages": 1, "commands": 1, "native-files": 2,
    "native-antidebug": 3, "anti-frida": 3,
}

DIAGNOSTIC_MAX_DUMPS = BOUNDED_CAPTURE.max_artifacts
DIAGNOSTIC_MAX_DUMP_BYTES = BOUNDED_CAPTURE.max_artifact_bytes
DIAGNOSTIC_MAX_TOTAL_BYTES = BOUNDED_CAPTURE.max_total_bytes
ADB_COMMAND_TIMEOUT_SECONDS = max(5, int(os.environ.get("MOB_AI_ADB_TIMEOUT_SECONDS", "30")))
ADB_INSTALL_TIMEOUT_SECONDS = max(ADB_COMMAND_TIMEOUT_SECONDS, 180)
ADB_TRANSPORT_MARKER = "MOB_AI_ADB_TRANSPORT_ERROR "
ADB_TRANSPORT_PATTERN = re.compile(
    r"device\s+offline|device\s+unauthorized|no devices?/emulators? found|"
    r"device ['\"]?.+?['\"]? not found|cannot connect|connection refused|"
    r"connection (?:closed|reset)|transport error|protocol fault|closed$",
    re.I | re.M,
)


class AdbTransportError(RuntimeError):
    def __init__(self, device: str, command: list[str], reason: str, *, timeout: int | None = None):
        self.device = device
        self.command = command
        self.reason = reason
        self.timeout = timeout
        super().__init__(f"ADB transport for {device or 'unknown device'} {reason}")

    def public_dict(self) -> dict[str, object]:
        return {
            "device": self.device,
            "reason": self.reason,
            "timeout_seconds": self.timeout,
            "command": " ".join(self.command[2:] if len(self.command) > 2 else self.command),
        }


def run(
    cmd: list[str], *, log: Path | None = None, check: bool = True,
    timeout: int | None = None, display: str | None = None, input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    shown = display or " ".join(cmd)
    print(f"+ {shown}")
    result = subprocess.run(
        cmd, text=True, input=input_text, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=timeout,
    )
    if log:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(result.stdout, encoding="utf-8", errors="replace")
    if result.stdout:
        print(result.stdout, end="")
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {shown}")
    return result


def run_adb_command(
    command: list[str], *, device: str, check: bool = True,
    timeout: int | None = None, display: str | None = None, input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one bounded ADB command and distinguish transport loss from command failure."""
    deadline = timeout or ADB_COMMAND_TIMEOUT_SECONDS
    try:
        result = run(
            command, check=False, timeout=deadline, display=display, input_text=input_text,
        )
    except subprocess.TimeoutExpired as error:
        raise AdbTransportError(
            device, command, f"timed out after {deadline} seconds", timeout=deadline,
        ) from error
    output = result.stdout or ""
    state = output.strip().lower() if command[-1:] == ["get-state"] else ""
    if ADB_TRANSPORT_PATTERN.search(output) or state in {"offline", "unauthorized", "unknown"}:
        detail = next((line.strip() for line in output.splitlines() if line.strip()), "became unavailable")
        raise AdbTransportError(device, command, detail, timeout=deadline)
    if check and result.returncode:
        shown = display or " ".join(command)
        raise RuntimeError(f"Command failed ({result.returncode}): {shown}")
    return result


def timeout_output(error: subprocess.TimeoutExpired) -> str:
    output = error.stdout or b""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return str(output)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def find_package(decoded: Path) -> str | None:
    manifests = [decoded / "resources" / "AndroidManifest.xml", decoded / "AndroidManifest.xml"]
    for manifest in manifests:
        if manifest.exists():
            match = re.search(r'<manifest[^>]+package="([^"]+)"', manifest.read_text(encoding="utf-8", errors="ignore"))
            if match:
                return match.group(1)
    return None


def scan(decoded: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    allowed = {".java", ".kt", ".xml", ".smali", ".txt", ".json"}
    for path in decoded.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in allowed or path.stat().st_size > 2_000_000:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for kind, pattern in PATTERNS.items():
            matches = list(pattern.finditer(text))
            if matches:
                findings.append({
                    "kind": kind,
                    "file": str(path.relative_to(decoded)),
                    "matches": sorted({m.group(0) for m in matches})[:10],
                })
    return findings


def native_load_references(decoded: Path) -> dict[str, list[str]]:
    """Map library basenames to the decompiled files that explicitly load them."""
    references: dict[str, set[str]] = {}
    pattern = re.compile(r"(?:System|Runtime(?:\.getRuntime\(\))?)\.loadLibrary\(\s*[\"']([^\"']+)[\"']")
    candidates: list[Path]
    ripgrep = shutil.which("rg")
    if not ripgrep:
        bundled = sorted(Path("/usr/local/lib/node_modules/@openai/codex/node_modules/@openai").glob("codex-*/vendor/*/codex-path/rg"))
        ripgrep = str(bundled[0]) if bundled else None
    if ripgrep:
        result = subprocess.run(
            [ripgrep, "-l", "--color", "never", "--glob", "*.java", "--glob", "*.kt", "--glob", "*.smali", "loadLibrary", str(decoded)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60,
        )
        candidates = [Path(value) for value in result.stdout.splitlines() if value]
    else:
        candidates = list(decoded.rglob("*"))
    for path in candidates:
        if not path.is_file() or path.suffix.lower() not in {".java", ".kt", ".smali"} or path.stat().st_size > 2_000_000:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in pattern.finditer(text):
            references.setdefault(f"lib{match.group(1)}.so", set()).add(path.relative_to(decoded).as_posix())
    return {name: sorted(paths)[:20] for name, paths in references.items()}


def scan_native(apk: Path, decoded: Path | None = None) -> list[dict[str, object]]:
    """Inventory every bounded APK native library without guessing which ones matter."""
    libraries: list[dict[str, object]] = []
    load_references = native_load_references(decoded) if decoded and decoded.is_dir() else {}
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if not info.filename.startswith("lib/") or not info.filename.endswith(".so") or info.file_size > 100_000_000:
                continue
            parts = Path(info.filename).parts
            if len(parts) != 3 or any(part in {"", ".", ".."} for part in parts):
                continue
            data = archive.read(info)
            libraries.append({
                "archive_path": info.filename,
                "abi": parts[1],
                "name": parts[2],
                "size": info.file_size,
                "sha256": hashlib.sha256(data).hexdigest(),
                "load_references": load_references.get(parts[2], []),
            })
    return sorted(libraries, key=lambda item: (str(item["abi"]), str(item["name"])))


def group_native_libraries(libraries: list[dict[str, object]]) -> list[dict[str, object]]:
    """Group equivalent APK libraries across ABIs into logical analysis targets."""
    grouped: dict[str, dict[str, object]] = {}
    for item in libraries:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        archive_path = str(item.get("archive_path") or "")
        abi = str(item.get("abi") or "")
        if not name or not archive_path or not abi:
            continue
        group = grouped.setdefault(name, {
            "library": name,
            "load_references": [],
            "variants": [],
        })
        references = set(group["load_references"])
        references.update(str(value) for value in item.get("load_references", []) if value)
        group["load_references"] = sorted(references)[:20]
        group["variants"].append({
            key: item[key] for key in ("archive_path", "abi", "size", "sha256") if key in item
        })
    for group in grouped.values():
        group["variants"] = sorted(group["variants"], key=lambda item: str(item.get("abi", "")))
    return sorted(grouped.values(), key=lambda item: str(item["library"]))


def prepare(apk: Path, runs: Path, reuse_static: Path | None = None) -> tuple[Path, dict[str, object]]:
    digest = sha256(apk)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = runs / f"{stamp}-{digest[:12]}"
    run_dir.mkdir(parents=True)
    original = run_dir / "original.apk"
    shutil.copy2(apk, original)
    original.chmod(0o444)
    if reuse_static is not None:
        source = reuse_static.resolve()
        source_report = source / "report.json"
        source_apk = source / "original.apk"
        if not source_report.is_file() or not source_apk.is_file() or sha256(source_apk) != digest:
            raise RuntimeError("Static-analysis reuse requires a prior run with the same APK hash")
        metadata = json.loads(source_report.read_text(encoding="utf-8"))
        for name in ("jadx", "native"):
            prior = source / name
            if prior.is_dir():
                ignore = shutil.ignore_patterns("selected") if name == "native" else None
                shutil.copytree(prior, run_dir / name, copy_function=shutil.copy2, ignore=ignore)
        metadata["findings"] = [
            item for item in metadata.get("findings", [])
            if not isinstance(item, dict) or item.get("kind") != "native_indicator"
        ]
        if not isinstance(metadata.get("native_libraries"), list):
            metadata["native_libraries"] = scan_native(original, run_dir / "jadx")
        metadata["native_library_groups"] = group_native_libraries(metadata["native_libraries"])
        metadata.update({
            "created_utc": stamp,
            "authorization_asserted": True,
            "source": str(apk.resolve()),
            "sha256": digest,
            "static_reused_from": str(source),
        })
        (run_dir / "report.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return run_dir, metadata
    decoded = run_dir / "jadx"
    run(["jadx", "--show-bad-code", "-d", str(decoded), str(original)], log=run_dir / "logs" / "jadx.log", check=False)
    findings = scan(decoded)
    native_libraries = scan_native(original, decoded)
    metadata: dict[str, object] = {
        "created_utc": stamp,
        "authorization_asserted": True,
        "source": str(apk.resolve()),
        "sha256": digest,
        "package": find_package(decoded),
        "findings": findings,
        "native_libraries": native_libraries,
        "native_library_groups": group_native_libraries(native_libraries),
    }
    (run_dir / "report.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return run_dir, metadata


def make_frida_scripts(run_dir: Path, iterations: int, modules: set[str] | None = None) -> list[Path]:
    template = (Path(__file__).parent / "frida" / "base-bypass.js").read_text(encoding="utf-8")
    selected = set(modules or DEFAULT_MODULES)
    scripts = []
    plan = []
    plan_path = run_dir / "adaptive-plan.json"
    previous_hashes: dict[str, str] = {}
    if plan_path.exists():
        try:
            previous = json.loads(plan_path.read_text(encoding="utf-8"))
            previous_hashes = {
                str(item["script"]): str(item["sha256"])
                for item in previous.get("iterations", [])
                if item.get("sha256") and not item.get("preserved_manual_edit", False)
            }
        except (json.JSONDecodeError, KeyError, TypeError):
            previous_hashes = {}
    for level in range(1, min(iterations, 3) + 1):
        target = run_dir / "frida" / f"bypass-level-{level}.js"
        target.parent.mkdir(parents=True, exist_ok=True)
        active = sorted(module for module in selected if MODULE_MIN_LEVEL[module] <= level)
        relative = str(target.relative_to(run_dir))
        rendered = template.replace("{{LEVEL}}", str(level)).replace("{{MODULES}}", json.dumps(active))
        preserved_manual = False
        if not target.exists() or previous_hashes.get(relative) == sha256(target):
            target.write_text(rendered, encoding="utf-8")
        else:
            preserved_manual = True
        scripts.append(target)
        plan.append({
            "iteration": level, "script": relative, "modules": active,
            "sha256": sha256(target), "preserved_manual_edit": preserved_manual,
        })
    plan_path.write_text(
        json.dumps({"selected_modules": sorted(selected), "iterations": plan}, indent=2), encoding="utf-8"
    )
    return scripts


def install_observer(run_dir: Path) -> Path:
    target = run_dir / "frida" / "observe.js"
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copy2(Path(__file__).parent / "frida" / "observe.js", target)
    return target


def parse_observation_events(output: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for match in re.finditer(r"MOB_AI_EVENT\s+(\{[^\r\n]+\})", output):
        try:
            event = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("source") != "mob-ai-observe":
            continue
        key = (str(event.get("kind", "")), str(event.get("detail", "")), str(event.get("stack", "")))
        if key not in seen:
            seen.add(key)
            events.append(event)
        if len(events) >= 500:
            break
    return events


def infer_modules(metadata: dict[str, object], events: list[dict[str, object]]) -> set[str]:
    modules: set[str] = set()
    static_map = {
        "root_framework": {"rootbeer", "java-files", "packages"},
        "root_binary": {"java-files", "commands", "native-files"},
        "root_property": {"properties"},
        "hook_framework": {"anti-frida"},
        "debugger": {"debugger", "native-antidebug"},
    }
    event_map = {
        "java-file": {"java-files"}, "debugger": {"debugger"},
        "system-property": {"properties"}, "process-command": {"commands"},
        "package-query": {"packages"}, "native-file": {"native-files"},
        "native-antidebug": {"native-antidebug"}, "anti-frida": {"anti-frida"},
    }
    for finding in metadata.get("findings", []):
        if not isinstance(finding, dict):
            continue
        kind = str(finding.get("kind", ""))
        modules.update(static_map.get(kind, set()))
    for event in events:
        modules.update(event_map.get(str(event.get("kind", "")), set()))
    # A quiet/obfuscated app still receives a conservative Java baseline. More
    # invasive native and anti-Frida hooks remain evidence-gated.
    if not modules:
        modules.update({"java-files", "debugger", "properties", "rootbeer", "packages", "commands"})
    return modules


def quiet_frida_command(
    args: argparse.Namespace, package: str, script: Path, duration_seconds: int,
) -> list[str]:
    """Keep a non-interactive Frida session attached for the full evidence window."""
    return [
        "frida", "-H", args.frida_endpoint, "-f", package, "-l", str(script),
        "-q", "-t", str(duration_seconds), "--exit-on-error",
    ]


def run_observation(args: argparse.Namespace, run_dir: Path, package: str) -> dict[str, object]:
    script = install_observer(run_dir)
    adb(args, "logcat", "-c", check=False)
    log = run_dir / "logs" / "observation-frida.log"
    cmd = quiet_frida_command(args, package, script, args.observation_seconds)
    print(f"Observation pass: {args.observation_seconds}s (no return values are modified)")
    try:
        result = run(
            cmd, log=log, check=False,
            timeout=args.observation_seconds + FRIDA_SHUTDOWN_GRACE_SECONDS,
        )
        frida_output = result.stdout
    except subprocess.TimeoutExpired as exc:
        frida_output = timeout_output(exc)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(frida_output, encoding="utf-8", errors="replace")
    logcat = adb(args, "logcat", "-d", "-t", "500", check=False).stdout
    (run_dir / "logs" / "observation-logcat.log").write_text(logcat, encoding="utf-8", errors="replace")
    diagnostic_files: dict[str, str] = {}
    if getattr(args, "diagnostics", False):
        diagnostic_commands = {
            "crash_buffer": ("logcat", "-b", "crash", "-d", "-t", "1000"),
            "exit_info": ("shell", "dumpsys", "activity", "exit-info", package),
            "native_crashes": ("shell", "dumpsys", "dropbox", "--print", "data_app_native_crash"),
            "tombstone_access": ("shell", "ls", "-lt", "/data/tombstones"),
        }
        for name, command in diagnostic_commands.items():
            output = adb(args, *command, check=False)
            content = "\n".join(part for part in (output.stdout, output.stderr) if part)
            destination = run_dir / "logs" / f"diagnostic-{name.replace('_', '-')}.log"
            destination.write_text(content, encoding="utf-8", errors="replace")
            diagnostic_files[name] = str(destination.relative_to(run_dir))
    events = parse_observation_events(frida_output)
    summary: dict[str, object] = {
        "duration_seconds": args.observation_seconds,
        "event_count": len(events),
        "events": events,
        "diagnostics": diagnostic_files,
    }
    (run_dir / "observations.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Observation events captured: {len(events)}")
    return {**summary, "frida_output": frida_output, "logcat": logcat}


def parse_diagnostic_actions(value: str) -> list[str]:
    actions = list(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))
    unknown = sorted(set(actions) - DIAGNOSTIC_ACTIONS)
    if unknown:
        raise RuntimeError(f"Unsupported diagnostic actions: {', '.join(unknown)}")
    if not actions:
        raise RuntimeError("At least one diagnostic action is required")
    if len(actions) > DIAGNOSTIC_MAX_ACTIONS_PER_PASS:
        raise RuntimeError(
            f"A diagnostic pass may request at most {DIAGNOSTIC_MAX_ACTIONS_PER_PASS} actions"
        )
    return actions


def parse_process_mappings(value: str) -> list[dict[str, object]]:
    mappings: list[dict[str, object]] = []
    pattern = re.compile(
        r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+(?P<perms>[-rwxps]{4})\s+"
        r"(?P<offset>[0-9a-f]+)\s+\S+\s+\d+\s*(?P<path>.*)$", re.I,
    )
    for line in value.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        start, end = int(match["start"], 16), int(match["end"], 16)
        mappings.append({
            "start": start, "end": end, "size": end - start,
            "permissions": match["perms"], "offset": int(match["offset"], 16),
            "path": match["path"].strip(),
        })
    return mappings


def embedded_payload_candidates(path: Path) -> list[tuple[int, bytes, str]]:
    """Carve bounded embedded ELF/DEX images with explicit file-size headers."""
    data = path.read_bytes()
    candidates: list[tuple[int, bytes, str]] = []
    for magic, kind in ((b"\x7fELF", "elf"), (b"dex\n", "dex"), (b"cdex", "cdex")):
        offset = data.find(magic, 1)
        while offset >= 0 and len(candidates) < DIAGNOSTIC_MAX_DUMPS:
            length = 0
            try:
                if kind == "dex":
                    length = struct.unpack_from("<I", data, offset + 32)[0]
                elif kind == "elf":
                    elf_class, encoding = data[offset + 4], data[offset + 5]
                    endian = "<" if encoding == 1 else ">"
                    if elf_class == 2:
                        phoff = struct.unpack_from(endian + "Q", data, offset + 32)[0]
                        phentsize, phnum = struct.unpack_from(endian + "HH", data, offset + 54)
                        for index in range(min(phnum, 256)):
                            row = offset + phoff + index * phentsize
                            file_offset = struct.unpack_from(endian + "Q", data, row + 8)[0]
                            file_size = struct.unpack_from(endian + "Q", data, row + 32)[0]
                            length = max(length, file_offset + file_size)
                    elif elf_class == 1:
                        phoff = struct.unpack_from(endian + "I", data, offset + 28)[0]
                        phentsize, phnum = struct.unpack_from(endian + "HH", data, offset + 42)
                        for index in range(min(phnum, 256)):
                            row = offset + phoff + index * phentsize
                            file_offset = struct.unpack_from(endian + "I", data, row + 4)[0]
                            file_size = struct.unpack_from(endian + "I", data, row + 16)[0]
                            length = max(length, file_offset + file_size)
            except (IndexError, struct.error):
                length = 0
            if 40 <= length <= DIAGNOSTIC_MAX_DUMP_BYTES and offset + length <= len(data):
                candidates.append((offset, data[offset:offset + length], kind))
            offset = data.find(magic, offset + 1)
    return candidates


def run_adaptive_diagnostics(
    args: argparse.Namespace, run_dir: Path, package: str, actions: list[str],
) -> Path:
    """Execute an allowlisted, observation-only Frida diagnostic pass."""
    try:
        import frida  # type: ignore
    except ImportError as error:
        raise RuntimeError("The Frida Python bindings are required for adaptive diagnostics") from error

    diagnostics_root = run_dir / "diagnostics"
    diagnostics_root.mkdir(parents=True, exist_ok=True)
    number = 1
    while (diagnostics_root / f"pass-{number}").exists():
        number += 1
    pass_dir = diagnostics_root / f"pass-{number}"
    dumps_dir = pass_dir / "runtime-dumps"
    pass_dir.mkdir()
    template = (Path(__file__).parent / "frida" / "adaptive-diagnostics.js").read_text(encoding="utf-8")
    rendered = template.replace("{{ACTIONS}}", json.dumps(actions))
    script_path = pass_dir / "instrumentation.js"
    script_path.write_text(rendered, encoding="utf-8")

    events: list[dict[str, object]] = []
    artifacts: list[dict[str, object]] = []
    errors: list[str] = []
    total_bytes = 0

    def save_artifact(data: bytes, prefix: str, suffix: str, metadata: object) -> dict[str, object] | None:
        nonlocal total_bytes
        remaining = DIAGNOSTIC_MAX_TOTAL_BYTES - total_bytes
        bounded = bytes(data[:min(DIAGNOSTIC_MAX_DUMP_BYTES, remaining)])
        if not bounded or len(artifacts) >= DIAGNOSTIC_MAX_DUMPS:
            return None
        digest = hashlib.sha256(bounded).hexdigest()
        for existing in artifacts:
            if existing.get("sha256") == digest:
                return existing
        dumps_dir.mkdir(exist_ok=True)
        destination = dumps_dir / f"{prefix}-{len(artifacts) + 1}-{digest[:12]}.{suffix}"
        destination.write_bytes(bounded)
        total_bytes += len(bounded)
        artifact = {
            "path": str(destination.relative_to(run_dir)), "sha256": digest,
            "size": len(bounded), "metadata": metadata or {},
        }
        artifacts.append(artifact)
        return artifact

    def on_message(message: dict[str, object], data: bytes | None) -> None:
        nonlocal total_bytes
        if message.get("type") == "error":
            errors.append(str(message.get("stack") or message.get("description") or message)[:4000])
            return
        payload = message.get("payload")
        if message.get("type") == "log" and isinstance(payload, str) and payload.startswith("MOB_AI_EVENT "):
            try:
                observed = json.loads(payload.removeprefix("MOB_AI_EVENT "))
            except json.JSONDecodeError:
                return
            if isinstance(observed, dict):
                observed["captured_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
                if len(events) < 1000:
                    events.append(observed)
            return
        if not isinstance(payload, dict) or payload.get("source") != "mob-ai-diagnostics":
            return
        event = dict(payload)
        event["captured_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        if payload.get("kind") in {"runtime-payload", "runtime-dex"} and data:
            kind = str(payload.get("kind"))
            artifact = save_artifact(
                bytes(data), "dex" if kind == "runtime-dex" else "payload",
                "dex" if kind == "runtime-dex" else "bin", payload.get("detail") or {},
            )
            if artifact:
                event["artifact"] = artifact
        if len(events) < 1000:
            events.append(event)

    device = frida.get_device_manager().add_remote_device(args.frida_endpoint)
    adb(args, "logcat", "-c", check=False)

    def live_pid() -> int | None:
        for _ in range(20):
            probe = adb(args, "shell", "pidof", package, check=False)
            value = (probe.stdout or "").strip().split()
            if value and value[0].isdigit():
                return int(value[0])
            time.sleep(0.1)
        return None

    def clean_launch() -> int | None:
        adb(args, "shell", "am", "force-stop", package, check=False)
        adb(
            args, "shell", "monkey", "-p", package,
            "-c", "android.intent.category.LAUNCHER", "1", check=False,
        )
        return live_pid()

    if "extract_embedded_payload" in actions:
        targets = sorted((run_dir / "native" / "selected").rglob("*.so")) if (run_dir / "native" / "selected").is_dir() else []
        for target in targets:
            for offset, content, kind in embedded_payload_candidates(target):
                artifact = save_artifact(
                    content, f"embedded-{kind}", "dex" if kind in {"dex", "cdex"} else "so",
                    {"source": str(target.relative_to(run_dir)), "offset": offset, "kind": kind},
                )
                events.append({
                    "source": "mob-ai-diagnostics", "kind": "embedded-payload",
                    "detail": {"source": str(target.relative_to(run_dir)), "offset": offset, "format": kind},
                    "artifact": artifact, "captured_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                })

    if "compare_launch_modes" in actions:
        comparison: list[dict[str, object]] = []
        window = min(5, args.observation_seconds)
        for mode in ("clean", "empty_spawn", "late_attach"):
            adb(args, "shell", "am", "force-stop", package, check=False)
            session = None
            pid: int | None = None
            try:
                if mode == "empty_spawn":
                    pid = int(device.spawn([package]))
                    session = device.attach(pid)
                    script = session.create_script("send({source:'mob-ai-diagnostics',kind:'empty-agent-ready',detail:{}});")
                    script.on("message", on_message)
                    script.load()
                    device.resume(pid)
                else:
                    pid = clean_launch()
                    if mode == "late_attach" and pid:
                        session = device.attach(pid)
                        script = session.create_script("send({source:'mob-ai-diagnostics',kind:'late-agent-ready',detail:{}});")
                        script.on("message", on_message)
                        script.load()
                time.sleep(window)
                alive = live_pid()
                comparison.append({"mode": mode, "started_pid": pid, "alive_pid": alive, "survived": bool(alive)})
            except Exception as error:
                comparison.append({"mode": mode, "started_pid": pid, "survived": False, "error": str(error)})
            finally:
                if session is not None:
                    try:
                        session.detach()
                    except Exception:
                        pass
        (pass_dir / "launch-comparison.json").write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
        events.append({
            "source": "mob-ai-diagnostics", "kind": "launch-comparison", "detail": comparison,
            "captured_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        })

    if {"snapshot_process_mappings", "dump_new_executable_regions"}.intersection(actions):
        pid = clean_launch()
        if not pid:
            errors.append("External mapping snapshot could not find a live target process.")
        else:
            seen_mappings: set[tuple[int, int, str, str]] = set()
            deadline = time.monotonic() + args.observation_seconds
            while time.monotonic() < deadline:
                result = adb(args, "shell", "su", "-c", f"cat /proc/{pid}/maps", check=False)
                current = parse_process_mappings(result.stdout or "")
                if not current:
                    if not live_pid():
                        break
                    time.sleep(0.1)
                    continue
                for mapping in current:
                    key = (
                        int(mapping["start"]), int(mapping["end"]),
                        str(mapping["permissions"]), str(mapping["path"]),
                    )
                    if key in seen_mappings:
                        continue
                    seen_mappings.add(key)
                    if "x" not in str(mapping["permissions"]):
                        continue
                    suspicious = not mapping["path"] or re.search(r"memfd:|deleted|anon_inode", str(mapping["path"]), re.I)
                    events.append({
                        "source": "mob-ai-diagnostics", "kind": "external-executable-mapping",
                        "detail": mapping, "captured_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    })
                    if "dump_new_executable_regions" not in actions or not suspicious:
                        continue
                    size = min(int(mapping["size"]), DIAGNOSTIC_MAX_DUMP_BYTES)
                    page_size = 4096
                    command = [
                        "adb", "-s", args.device, "exec-out", "su", "-c",
                        f"dd if=/proc/{pid}/mem bs={page_size} skip={int(mapping['start']) // page_size} count={(size + page_size - 1) // page_size} status=none",
                    ]
                    try:
                        dumped = subprocess.run(command, capture_output=True, timeout=10, check=False)
                        if dumped.returncode == 0 and dumped.stdout:
                            save_artifact(dumped.stdout[:size], "external-map", "bin", mapping)
                        else:
                            errors.append(f"External dump failed for {int(mapping['start']):x}: {(dumped.stderr or b'')[:500]!r}")
                    except (OSError, subprocess.SubprocessError) as error:
                        errors.append(f"External dump failed for {int(mapping['start']):x}: {error}")
                time.sleep(0.1)
            (pass_dir / "process-mappings.json").write_text(
                json.dumps([event["detail"] for event in events if event.get("kind") == "external-executable-mapping"], indent=2) + "\n",
                encoding="utf-8",
            )

    orchestrated = {
        "compare_launch_modes", "snapshot_process_mappings",
        "dump_new_executable_regions", "extract_embedded_payload",
    }
    frida_actions = [action for action in actions if action not in orchestrated and action != "late_attach_observer"]
    if frida_actions or "late_attach_observer" in actions:
        pid: int | None = None
        session = None
        try:
            if "late_attach_observer" in actions:
                pid = clean_launch()
                if not pid:
                    raise RuntimeError("Late attach could not find a live target process")
                session = device.attach(pid)
            else:
                pid = int(device.spawn([package]))
                session = device.attach(pid)
            loaded_scripts = []
            if "late_attach_observer" in actions:
                observer_source = (Path(__file__).parent / "frida" / "observe.js").read_text(encoding="utf-8")
                observer_script = session.create_script(observer_source)
                observer_script.on("message", on_message)
                observer_script.load()
                loaded_scripts.append(observer_script)
            if frida_actions:
                script = session.create_script(rendered)
                script.on("message", on_message)
                script.load()
                loaded_scripts.append(script)
            if "late_attach_observer" not in actions:
                device.resume(pid)
            time.sleep(args.observation_seconds)
        except Exception as error:
            errors.append(f"{type(error).__name__}: {error}")
        finally:
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass

    logcat = adb(args, "logcat", "-d", "-t", "1000", check=False)
    (pass_dir / "logcat.log").write_text(
        (logcat.stdout or "") + (logcat.stderr or ""), encoding="utf-8", errors="replace",
    )
    exit_info = adb(args, "shell", "dumpsys", "activity", "exit-info", package, check=False)
    (pass_dir / "exit-info.log").write_text(
        (exit_info.stdout or "") + (exit_info.stderr or ""), encoding="utf-8", errors="replace",
    )
    manifest = {
        "version": 1, "pass": number, "package": package, "device": args.device,
        "actions": actions, "duration_seconds": args.observation_seconds,
        "recipes": [DIAGNOSTIC_RECIPES[action].public_dict() for action in actions],
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "limits": {
            "max_dumps": DIAGNOSTIC_MAX_DUMPS,
            "max_dump_bytes": DIAGNOSTIC_MAX_DUMP_BYTES,
            "max_total_bytes": DIAGNOSTIC_MAX_TOTAL_BYTES,
        },
        "events": events, "artifacts": artifacts, "errors": errors,
    }
    manifest_path = pass_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Adaptive diagnostic manifest: {manifest_path}")
    print(f"Diagnostic events: {len(events)}; runtime artifacts: {len(artifacts)}; errors: {len(errors)}")
    return manifest_path


def adb(args: argparse.Namespace, *extra: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    timeout = ADB_INSTALL_TIMEOUT_SECONDS if extra[:2] == ("install", "-r") else ADB_COMMAND_TIMEOUT_SECONDS
    return run_adb_command(
        ["adb", "-s", args.device, *extra], device=str(args.device or ""),
        check=check, timeout=timeout,
    )


def device_abi(args: argparse.Namespace) -> str:
    """Return the selected device's primary Android ABI, when ADB exposes it."""
    result = adb(args, "shell", "getprop", "ro.product.cpu.abi", check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def validate_adb_endpoint(value: str) -> str:
    match = re.fullmatch(r"(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})", value)
    if not match or not 1 <= int(match.group(1)) <= 65535:
        raise RuntimeError(f"Invalid ADB endpoint: {value!r}; expected HOST:PORT")
    return value


def setup_wireless(args: argparse.Namespace) -> None:
    """Pair if requested, connect, verify, and select the wireless ADB serial."""
    connect_endpoint = validate_adb_endpoint(args.wireless_connect)
    if args.wireless_pair:
        pair_endpoint = validate_adb_endpoint(args.wireless_pair)
        pairing_code = args.wireless_pair_code or os.environ.get("MOB_AI_ADB_PAIRING_CODE")
        if not pairing_code and sys.stdin.isatty():
            pairing_code = getpass.getpass("Wireless debugging pairing code: ")
        if not pairing_code or not re.fullmatch(r"[0-9]{6}", pairing_code):
            raise RuntimeError("A six-digit pairing code is required via prompt, --wireless-pair-code, or MOB_AI_ADB_PAIRING_CODE")
        pair_result = run_adb_command(
            ["adb", "pair", pair_endpoint],
            device=pair_endpoint,
            check=False,
            timeout=ADB_COMMAND_TIMEOUT_SECONDS,
            display=f"adb pair {pair_endpoint} (pairing code supplied securely)",
            input_text=pairing_code + "\n",
        )
        if pair_result.returncode or "successfully paired" not in pair_result.stdout.lower():
            raise RuntimeError(f"Wireless ADB pairing failed for {pair_endpoint}")
    connect_result = run_adb_command(
        ["adb", "connect", connect_endpoint], device=connect_endpoint,
        check=False, timeout=ADB_COMMAND_TIMEOUT_SECONDS,
    )
    if connect_result.returncode or not re.search(r"(?:connected to|already connected to)", connect_result.stdout, re.I):
        raise RuntimeError(f"Wireless ADB connection failed for {connect_endpoint}")
    if args.device and args.device != connect_endpoint:
        raise RuntimeError("--device must match --wireless-connect when both are supplied")
    args.device = connect_endpoint
    state = run_adb_command(
        ["adb", "-s", args.device, "get-state"], device=args.device,
        check=False, timeout=ADB_COMMAND_TIMEOUT_SECONDS,
    )
    if state.returncode or state.stdout.strip() != "device":
        raise RuntimeError(f"Wireless device {args.device} is not in the adb 'device' state")
    print(f"Wireless ADB device selected: {args.device}")


def prepare_device(args: argparse.Namespace, apk: Path) -> None:
    adb(args, "get-state")
    if args.install:
        adb(args, "install", "-r", str(apk))
    if args.start_frida_server:
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", args.start_frida_server):
            raise RuntimeError("--start-frida-server must be a simple absolute device path")
        probe = adb(args, "shell", "su", "-c", f"test -x {args.start_frida_server}", check=False)
        if probe.returncode:
            raise RuntimeError(
                f"Frida Server is missing or not executable at {args.start_frida_server}"
            )
        adb(args, "shell", "su", "-c", f"{args.start_frida_server} -D &")
        time.sleep(2)
    if args.frida_endpoint == "127.0.0.1:27042":
        adb(args, "forward", "tcp:27042", "tcp:27042")
    if args.start_frida_server:
        probe = run(
            ["frida-ps", "-H", args.frida_endpoint], check=False, timeout=15,
            display=f"frida-ps -H {args.frida_endpoint} (server readiness check)",
        )
        if probe.returncode:
            raise RuntimeError(
                f"Frida Server started from {args.start_frida_server} but is not reachable at {args.frida_endpoint}"
            )


def load_success_spec(path: Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("mode", "all") not in {"all", "any"}:
        raise RuntimeError("Success spec must be an object with mode 'all' or 'any'")
    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise RuntimeError("Success spec requires a non-empty 'checks' array")
    allowed = {
        "process_alive", "foreground_package", "activity_reached", "no_crash",
        "ui_text_regex", "ui_text_not_regex", "log_regex", "frida_regex",
        "output_regex", "log_not_regex",
    }
    for index, check in enumerate(checks, 1):
        if not isinstance(check, dict) or check.get("type") not in allowed:
            raise RuntimeError(f"Invalid success check #{index}; supported types: {', '.join(sorted(allowed))}")
        if check["type"] == "activity_reached" and (
            not isinstance(check.get("activity"), str) or not check["activity"]
        ):
            raise RuntimeError(f"Success check #{index} requires a non-empty activity name")
        if check["type"] in {
            "ui_text_regex", "ui_text_not_regex", "log_regex", "frida_regex",
            "output_regex", "log_not_regex",
        }:
            if not isinstance(check.get("pattern"), str) or not check["pattern"]:
                raise RuntimeError(f"Success check #{index} requires a non-empty regex pattern")
            try:
                re.compile(check["pattern"])
            except re.error as error:
                raise RuntimeError(f"Invalid regex in success check #{index}: {error}") from error
    repeat = data.get("repeat", 1)
    min_passes = data.get("min_passes", repeat)
    if not isinstance(repeat, int) or not 1 <= repeat <= 3:
        raise RuntimeError("Success spec 'repeat' must be an integer from 1 to 3")
    if not isinstance(min_passes, int) or not 1 <= min_passes <= repeat:
        raise RuntimeError("Success spec 'min_passes' must be between 1 and repeat")
    return {
        "mode": data.get("mode", "all"), "checks": checks,
        "repeat": repeat, "min_passes": min_passes,
        "baseline_required": bool(data.get("baseline_required", False)),
        "name": str(data.get("name") or "Success policy"),
    }


def evaluate_success(
    args: argparse.Namespace, package: str, frida_output: str, logcat: str,
    spec: dict[str, object] | None,
) -> tuple[bool, list[dict[str, object]]]:
    if spec is None:
        if not args.success_regex:
            return False, []
        matched = re.search(args.success_regex, frida_output + "\n" + logcat, re.I | re.M) is not None
        return matched, [{"type": "output_regex", "pattern": args.success_regex, "passed": matched}]

    results: list[dict[str, object]] = []
    ui_xml: str | None = None

    def get_ui_xml() -> str:
        nonlocal ui_xml
        if ui_xml is None:
            remote = "/sdcard/mob-ai-window.xml"
            dumped = adb(args, "shell", "uiautomator", "dump", remote, check=False)
            if dumped.returncode == 0:
                ui_xml = adb(args, "shell", "cat", remote, check=False).stdout
            else:
                ui_xml = ""
            adb(args, "shell", "rm", "-f", remote, check=False)
        return ui_xml

    for check in spec["checks"]:
        kind = str(check["type"])
        result: dict[str, object] = {"type": kind, "passed": False}
        if kind == "process_alive":
            probe = adb(args, "shell", "pidof", package, check=False)
            result.update(passed=probe.returncode == 0 and bool(probe.stdout.strip()), evidence=probe.stdout.strip()[:500])
        elif kind == "foreground_package":
            expected = str(check.get("package") or package)
            probe = adb(args, "shell", "dumpsys", "activity", "activities", check=False)
            resumed = "\n".join(line.strip() for line in probe.stdout.splitlines() if "ResumedActivity" in line)
            result.update(package=expected, passed=expected in resumed, evidence=resumed[:500])
        elif kind == "activity_reached":
            expected = str(check["activity"])
            probe = adb(args, "shell", "dumpsys", "activity", "activities", check=False)
            resumed = "\n".join(
                line.strip() for line in probe.stdout.splitlines()
                if "ResumedActivity" in line or "topResumedActivity" in line
            )
            result.update(activity=expected, passed=expected in resumed, evidence=resumed[:500])
        elif kind == "no_crash":
            crash_pattern = (
                r"FATAL EXCEPTION|AndroidRuntime.*Process:|has died:|Force finishing activity|"
                r"Fatal signal\s+\d+|signal\s+\d+\s+\(SIG(?:SEGV|BUS|ABRT|ILL|FPE)\)|"
                r"APP CRASH\((?:NATIVE|EXCEPTION)\)"
            )
            matched = re.search(crash_pattern, logcat, re.I | re.M) is not None
            result.update(passed=not matched, pattern=crash_pattern)
        else:
            pattern = str(check["pattern"])
            if kind in {"ui_text_regex", "ui_text_not_regex"}:
                haystack = get_ui_xml()
            else:
                haystack = {
                    "log_regex": logcat,
                    "log_not_regex": logcat,
                    "frida_regex": frida_output,
                    "output_regex": frida_output + "\n" + logcat,
                }[kind]
            matched = re.search(pattern, haystack, re.I | re.M) is not None
            passed = not matched if kind in {"log_not_regex", "ui_text_not_regex"} else matched
            result.update(pattern=pattern, passed=passed)
            if kind.startswith("ui_text_"):
                result["evidence"] = haystack[:500]
        results.append(result)
    passed_values = [bool(result["passed"]) for result in results]
    success = all(passed_values) if spec["mode"] == "all" else any(passed_values)
    return success, results


def run_frida(
    args: argparse.Namespace, run_dir: Path, package: str, scripts: list[Path],
    success_spec: dict[str, object] | None,
) -> tuple[bool, list[dict[str, object]]]:
    success = False
    attempts: list[dict[str, object]] = []
    repeat = int(success_spec.get("repeat", 1)) if success_spec else 1
    min_passes = int(success_spec.get("min_passes", repeat)) if success_spec else 1
    for index, script in enumerate(scripts, 1):
        repetitions: list[dict[str, object]] = []
        pass_count = 0
        for repetition in range(1, repeat + 1):
            # Each validation starts from the same stopped state so a surviving
            # process from the baseline or prior repeat cannot create a false pass.
            adb(args, "shell", "am", "force-stop", package, check=False)
            adb(args, "logcat", "-c", check=False)
            cmd = quiet_frida_command(args, package, script, args.run_seconds)
            suffix = "" if repetition == 1 else f"-repeat-{repetition}"
            log = run_dir / "logs" / f"frida-{index}{suffix}.log"
            print(
                f"Iteration {index}, validation {repetition}/{repeat}: "
                f"{script.name} ({args.run_seconds}s observation window)"
            )
            try:
                result = run(
                    cmd, log=log, check=False,
                    timeout=args.run_seconds + FRIDA_SHUTDOWN_GRACE_SECONDS,
                )
            except subprocess.TimeoutExpired as exc:
                output = timeout_output(exc)
                log.write_text(output, encoding="utf-8", errors="replace")
                result = None
            logcat = adb(args, "logcat", "-d", "-t", "500", check=False).stdout
            logcat_log = run_dir / "logs" / f"logcat-{index}{suffix}.log"
            logcat_log.write_text(logcat, encoding="utf-8", errors="replace")
            frida_output = log.read_text(encoding="utf-8", errors="ignore")
            passed, checks = evaluate_success(args, package, frida_output, logcat, success_spec)
            pass_count += int(passed)
            repetitions.append({"repeat": repetition, "passed": passed, "checks": checks})
            if result is not None and result.returncode != 0:
                print("Frida exited early; inspect the validation log.", file=sys.stderr)
        success = pass_count >= min_passes
        attempts.append({
            "iteration": index, "script": str(script.relative_to(run_dir)),
            "passed": success, "pass_count": pass_count, "required_passes": min_passes,
            "repetitions": repetitions,
        })
        if success:
            print(f"Success policy passed at iteration {index} ({pass_count}/{repeat} validations).")
            break
    return success, attempts


def validate_candidate_script(run_dir: Path, value: Path) -> Path:
    candidate = value.resolve()
    try:
        candidate.relative_to(run_dir.resolve())
    except ValueError as error:
        raise RuntimeError("--candidate-script must be inside the selected run directory") from error
    if candidate.suffix.lower() != ".js" or not candidate.is_file():
        raise RuntimeError("--candidate-script must name an existing .js file")
    try:
        import frida
        frida.Compiler().build(str(candidate))
    except Exception as error:
        raise RuntimeError(f"Candidate Frida script did not compile: {error}") from error
    return candidate


def rebuild(args: argparse.Namespace, run_dir: Path) -> Path:
    decoded = run_dir / "apktool"
    run(["apktool", "d", "-f", str(run_dir / "original.apk"), "-o", str(decoded)], log=run_dir / "logs" / "apktool-decode.log")
    patch_script = Path(args.patch_script).resolve() if args.patch_script else run_dir / "patch.py"
    if not args.patch_script:
        patch_script.write_text(
            "#!/usr/bin/env python3\n"
            "# Edit this file to make narrowly scoped, reviewed changes under apktool/.\n"
            "# Then rerun with: --strategy rebuild --resume RUN_DIR --patch-script RUN_DIR/patch.py\n"
            "raise SystemExit('No static patch has been authored yet')\n",
            encoding="utf-8",
        )
        raise RuntimeError(f"Static rebuild selected. Review findings and implement {patch_script} before continuing.")
    run([sys.executable, str(patch_script), str(decoded)], log=run_dir / "logs" / "patch.log")
    unsigned = run_dir / "rebuilt-unsigned.apk"
    run(["apktool", "b", str(decoded), "-o", str(unsigned)], log=run_dir / "logs" / "apktool-build.log")
    signed_dir = run_dir / "signed"
    run(["uber-apk-signer", "--apks", str(unsigned), "--out", str(signed_dir)], log=run_dir / "logs" / "sign.log")
    signed = next(signed_dir.glob("*.apk"))
    print(f"Signed test APK: {signed}")
    return signed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", nargs="?", type=Path, help="APK to assess")
    parser.add_argument("--authorized", action="store_true", help="assert ownership or explicit testing authorization")
    parser.add_argument("--strategy", choices=("choose", "frida", "rebuild"), default="choose")
    parser.add_argument("--device", help="exact adb serial for an emulator or physical test device")
    parser.add_argument("--wireless-connect", metavar="HOST:PORT", help="connect to this Android wireless-debugging endpoint and select it as --device")
    parser.add_argument("--wireless-pair", metavar="HOST:PORT", help="pair first using the separate pairing endpoint shown by Android")
    parser.add_argument("--wireless-pair-code", help="six-digit pairing code; prefer the prompt or MOB_AI_ADB_PAIRING_CODE to avoid shell history")
    parser.add_argument("--package", help="override the detected Android package")
    parser.add_argument("--install", action="store_true", help="install/replace the APK on the selected device")
    parser.add_argument("--iterations", type=int, default=3, choices=(1, 2, 3))
    parser.add_argument("--run-seconds", type=int, default=20)
    parser.add_argument("--success-regex", help="stop when this regex appears in Frida/logcat output")
    parser.add_argument("--success-spec", type=Path, help="JSON success policy with all/any structured checks")
    parser.add_argument("--observation-mode", choices=("off", "before", "only"), default="before", help="run non-mutating discovery before adaptive bypasses")
    parser.add_argument("--observation-seconds", type=int, default=15)
    parser.add_argument("--diagnostics", action="store_true", help="capture Android crash-buffer, exit-info, and available tombstone evidence")
    parser.add_argument(
        "--diagnostic-actions",
        help="comma-separated allowlisted adaptive diagnostic recipes; runs one bounded diagnostic pass and exits",
    )
    parser.add_argument("--candidate-script", type=Path, help="execute one reviewed .js candidate inside the resumed run")
    parser.add_argument("--frida-endpoint", default="127.0.0.1:27042", help="frida-server host:port")
    parser.add_argument("--frida-version", default="", help="installed isolated Frida client version")
    parser.add_argument("--start-frida-server", help="device path to an already-installed frida-server (requires su)")
    parser.add_argument("--patch-script", help="reviewed Python patch receiving the apktool directory")
    parser.add_argument("--resume", type=Path, help="resume an existing run directory")
    parser.add_argument("--reuse-static", type=Path, help="reuse JADX/native static artifacts from a prior run of the identical APK")
    parser.add_argument("--runs", type=Path, default=Path("/workspace/runs"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    activate_frida_runtime(args.frida_version)
    if not args.authorized:
        print("Refusing to run without --authorized (ownership or explicit testing permission).", file=sys.stderr)
        return 2
    if args.wireless_pair and not args.wireless_connect:
        raise RuntimeError("--wireless-pair also requires --wireless-connect; Android normally uses different pairing and connection ports")
    if args.wireless_pair_code and not args.wireless_pair:
        raise RuntimeError("--wireless-pair-code requires --wireless-pair")
    if args.success_regex and args.success_spec:
        raise RuntimeError("Use either --success-regex or --success-spec, not both")
    if args.run_seconds < 1 or args.observation_seconds < 1:
        raise RuntimeError("Run and observation durations must be positive")
    success_spec = load_success_spec(args.success_spec.resolve() if args.success_spec else None)
    if args.wireless_connect:
        setup_wireless(args)
    if args.resume:
        run_dir = args.resume.resolve()
        metadata = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    else:
        if not args.apk or not args.apk.is_file():
            print("An existing APK path is required unless --resume is used.", file=sys.stderr)
            return 2
        run_dir, metadata = prepare(args.apk.resolve(), args.runs.resolve(), args.reuse_static)
    print(f"Run directory: {run_dir}")
    print(f"Static findings: {len(metadata['findings'])}")
    strategy = args.strategy
    if strategy == "choose":
        if sys.stdin.isatty():
            selected = input("Strategy [frida/rebuild] (frida): ").strip().lower() or "frida"
            if selected not in {"frida", "rebuild"}:
                raise RuntimeError("Invalid strategy")
            strategy = selected
        else:
            strategy = "frida"
    if strategy == "rebuild":
        rebuild(args, run_dir)
        return 0
    observer = install_observer(run_dir)
    if not args.device:
        modules = infer_modules(metadata, [])
        scripts = make_frida_scripts(run_dir, args.iterations, modules)
        print(f"Generated observer: {observer}")
        print("Generated adaptive Frida iterations:", *(str(p) for p in scripts), sep="\n  ")
        print("No --device or --wireless-connect supplied; analysis and hook generation are complete. No device was changed.")
        return 0
    package = args.package or metadata.get("package")
    if not package:
        raise RuntimeError("Package name was not detected; pass --package explicitly.")
    prepare_device(args, run_dir / "original.apk")
    runtime_abi = device_abi(args)
    if args.diagnostic_actions:
        actions = parse_diagnostic_actions(args.diagnostic_actions)
        run_adaptive_diagnostics(args, run_dir, str(package), actions)
        return 0
    observation: dict[str, object] | None = None
    events: list[dict[str, object]] = []
    if args.observation_mode != "off":
        observation = run_observation(args, run_dir, str(package))
        events = list(observation["events"])
    elif (run_dir / "observations.json").exists():
        stored = json.loads((run_dir / "observations.json").read_text(encoding="utf-8"))
        events = list(stored.get("events", []))

    modules = infer_modules(metadata, events)
    scripts = make_frida_scripts(run_dir, args.iterations, modules)
    if args.candidate_script:
        scripts = [validate_candidate_script(run_dir, args.candidate_script)]
    print("Adaptive modules:", ", ".join(sorted(modules)))
    print("Generated Frida iterations:", *(str(p) for p in scripts), sep="\n  ")

    baseline: dict[str, object] | None = None
    if observation is not None and success_spec is not None:
        baseline_passed, baseline_checks = evaluate_success(
            args, str(package), str(observation["frida_output"]),
            str(observation["logcat"]), success_spec,
        )
        baseline = {"passed": baseline_passed, "checks": baseline_checks}

    if args.observation_mode == "only":
        assert observation is not None
        if baseline is None:
            success, checks = evaluate_success(
                args, str(package), str(observation["frida_output"]),
                str(observation["logcat"]), success_spec,
            )
            baseline = {"passed": success, "checks": checks}
        else:
            success, checks = bool(baseline["passed"]), list(baseline["checks"])
        summary = {
            "strategy": "observation", "device": args.device,
            "frida_version": args.frida_version,
            "device_abi": runtime_abi,
            "transport": "wireless" if args.wireless_connect else "adb",
            "package": package, "observation_events": len(events),
            "adaptive_modules": sorted(modules), "success": success, "checks": checks,
            "baseline": baseline,
            "success_policy": success_spec,
        }
        (run_dir / "result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return 0 if success or (success_spec is None and not args.success_regex) else 1

    if baseline and baseline["passed"] and success_spec.get("baseline_required"):
        summary = {
            "strategy": "observation", "device": args.device,
            "frida_version": args.frida_version,
            "device_abi": runtime_abi,
            "transport": "wireless" if args.wireless_connect else "adb",
            "package": package, "observation_events": len(events),
            "adaptive_modules": sorted(modules), "success": True,
            "baseline": baseline, "success_policy": success_spec, "attempts": [],
        }
        (run_dir / "result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print("Baseline already satisfies the policy; no bypass candidate was required.")
        return 0

    success, attempts = run_frida(args, run_dir, str(package), scripts, success_spec)
    summary = {
        "strategy": "frida", "device": args.device,
        "frida_version": args.frida_version,
        "device_abi": runtime_abi,
        "transport": "wireless" if args.wireless_connect else "adb",
        "package": package, "observation_events": len(events),
        "adaptive_modules": sorted(modules), "success": success,
        "baseline": baseline,
        "success_policy": success_spec or ({"legacy_regex": args.success_regex} if args.success_regex else None),
        "attempts": attempts,
    }
    (run_dir / "result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0 if success or (success_spec is None and not args.success_regex) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdbTransportError as error:
        print(ADB_TRANSPORT_MARKER + json.dumps(error.public_dict(), separators=(",", ":")), file=sys.stderr)
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(3)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

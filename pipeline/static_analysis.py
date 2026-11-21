"""APK decompilation, static findings, and bounded native-library inventory."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Callable
import zipfile


PATTERNS = {
    "root_framework": re.compile(r"RootBeer|Magisk|SuperSU|rooted|isRooted", re.I),
    "root_binary": re.compile(r"(/system/(?:x?bin)/su|/sbin/su|which\s+su)", re.I),
    "root_property": re.compile(r"ro\.(?:debuggable|secure)|test-keys|release-keys", re.I),
    "hook_framework": re.compile(r"frida|xposed|substrate|gum-js-loop|linjector", re.I),
    "debugger": re.compile(r"isDebuggerConnected|TracerPid|ptrace", re.I),
}


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
                    "matches": sorted({match.group(0) for match in matches})[:10],
                })
    return findings


def native_load_references(decoded: Path) -> dict[str, list[str]]:
    """Map library basenames to the decompiled files that explicitly load them."""
    references: dict[str, set[str]] = {}
    pattern = re.compile(r"(?:System|Runtime(?:\.getRuntime\(\))?)\.loadLibrary\(\s*[\"']([^\"']+)[\"']")
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
        group = grouped.setdefault(name, {"library": name, "load_references": [], "variants": []})
        references = set(group["load_references"])
        references.update(str(value) for value in item.get("load_references", []) if value)
        group["load_references"] = sorted(references)[:20]
        group["variants"].append({
            key: item[key] for key in ("archive_path", "abi", "size", "sha256") if key in item
        })
    for group in grouped.values():
        group["variants"] = sorted(group["variants"], key=lambda item: str(item.get("abi", "")))
    return sorted(grouped.values(), key=lambda item: str(item["library"]))


def prepare_static(
    apk: Path, runs: Path, *, command_runner: Callable, reuse_static: Path | None = None,
) -> tuple[Path, dict[str, object]]:
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
            "created_utc": stamp, "authorization_asserted": True,
            "source": str(apk.resolve()), "sha256": digest,
            "static_reused_from": str(source),
        })
        (run_dir / "report.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return run_dir, metadata
    decoded = run_dir / "jadx"
    command_runner(["jadx", "--show-bad-code", "-d", str(decoded), str(original)], log=run_dir / "logs" / "jadx.log", check=False)
    findings = scan(decoded)
    native_libraries = scan_native(original, decoded)
    metadata: dict[str, object] = {
        "created_utc": stamp, "authorization_asserted": True,
        "source": str(apk.resolve()), "sha256": digest,
        "package": find_package(decoded), "findings": findings,
        "native_libraries": native_libraries,
        "native_library_groups": group_native_libraries(native_libraries),
    }
    (run_dir / "report.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return run_dir, metadata

"""Native inventory validation, ABI selection, and verified extraction."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import zipfile

from assessment.runtime import (
    NATIVE_BATCH_SIZE, LoopError, normalize_android_abi, read_json, sha256, workspace_relative,
)


class NativeInventoryMixin:
    @staticmethod
    def _materialize_native_targets(
        run_dir: Path, raw_selected: list[Any], runtime_abi: str,
    ) -> list[dict[str, Any]]:
        report = read_json(run_dir / "report.json")
        groups = report.get("native_library_groups") or []
        available_groups = {
            str(item.get("library")): item
            for item in groups if isinstance(item, dict) and item.get("library")
        }
        if len(raw_selected) > NATIVE_BATCH_SIZE:
            raise LoopError(f"Native selection exceeded the {NATIVE_BATCH_SIZE}-library batch limit.")
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        with zipfile.ZipFile(run_dir / "original.apk") as archive:
            archive_names = set(archive.namelist())

            def extract_variant(variant: dict[str, Any], library: str) -> dict[str, Any]:
                archive_path = str(variant.get("archive_path") or "")
                abi = normalize_android_abi(str(variant.get("abi") or ""))
                if archive_path not in archive_names or not abi:
                    raise LoopError(f"Native inventory variant is unavailable for {library}: {archive_path}")
                destination = run_dir / "native" / "selected" / abi / library
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(archive_path))
                if sha256(destination) != str(variant.get("sha256") or ""):
                    raise LoopError(f"Extracted native library hash mismatch: {archive_path}")
                return {
                    "archive_path": archive_path, "abi": abi, "name": library,
                    "sha256": variant.get("sha256"), "extracted": workspace_relative(destination),
                }

            for raw in raw_selected:
                if not isinstance(raw, dict):
                    raise LoopError("Native selection contained a non-object target.")
                library = str(raw.get("library") or "")
                priority = str(raw.get("priority") or "")
                reason = str(raw.get("reason") or "").strip()
                if library not in available_groups:
                    raise LoopError(f"Native selection referenced a library outside the grouped inventory: {library}")
                if library in seen or priority not in {"high", "medium", "low"} or not reason:
                    raise LoopError(f"Native selection metadata is invalid for {library}.")
                seen.add(library)
                group = available_groups[library]
                variants = [item for item in group.get("variants", []) if isinstance(item, dict)]
                by_abi = {normalize_android_abi(str(item.get("abi") or "")): item for item in variants}
                if runtime_abi and runtime_abi in by_abi:
                    primary_abi = runtime_abi
                elif len(by_abi) == 1:
                    primary_abi = next(iter(by_abi))
                else:
                    raise LoopError(
                        f"Cannot select the matching ABI for {library}; recorded device ABI is "
                        f"{runtime_abi or 'unknown'} and available variants are {', '.join(sorted(by_abi))}."
                    )
                primary = extract_variant(by_abi[primary_abi], library)
                cross_value = raw.get("cross_abi")
                cross_result: dict[str, Any] | None = None
                if cross_value is not None:
                    if not isinstance(cross_value, dict):
                        raise LoopError(f"Cross-ABI request is invalid for {library}.")
                    cross_reason = str(cross_value.get("reason") or "").strip()
                    requested = cross_value.get("abis")
                    if not cross_reason or not isinstance(requested, list) or not requested:
                        raise LoopError(f"Cross-ABI comparison requires ABIs and a reason for {library}.")
                    normalized = [normalize_android_abi(str(value)) for value in requested]
                    if len(set(normalized)) != len(normalized) or primary_abi in normalized:
                        raise LoopError(f"Cross-ABI comparison duplicates a variant for {library}.")
                    if any(abi not in by_abi for abi in normalized):
                        raise LoopError(f"Cross-ABI comparison references an unavailable variant for {library}.")
                    cross_result = {
                        "reason": cross_reason,
                        "variants": [extract_variant(by_abi[abi], library) for abi in normalized],
                    }
                selected.append({
                    "library": library, "priority": priority, "reason": reason,
                    "load_references": group.get("load_references") or [], "primary": primary,
                    **({"cross_abi": cross_result} if cross_result else {}),
                })
        return selected


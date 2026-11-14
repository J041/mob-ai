"""Validated successful-hook lookup shared by the catalog and launcher."""

from __future__ import annotations

from pathlib import Path


def successful_candidate_path(directory: Path, loop: dict | None) -> str:
    """Return the successful candidate only when it is a bounded iteration artifact."""
    if not loop or loop.get("status") != "success":
        return ""
    for iteration in reversed(loop.get("iterations") or []):
        if not isinstance(iteration, dict) or not (iteration.get("validation") or {}).get("success"):
            continue
        candidate = str(iteration.get("candidate") or "").replace("\\", "/")
        marker = f"/runs/{directory.name}/"
        if marker in f"/{candidate.lstrip('/')}":
            relative = f"/{candidate.lstrip('/')}".split(marker, 1)[1]
        else:
            relative = candidate.lstrip("/")
        path = (directory / relative).resolve()
        try:
            bounded = path.relative_to(directory.resolve())
        except ValueError:
            continue
        parts = bounded.parts
        if (
            len(parts) == 3 and parts[0] == "agent"
            and parts[1].startswith("iteration-") and parts[2] == "candidate.js"
            and path.is_file()
        ):
            return bounded.as_posix()
    return ""

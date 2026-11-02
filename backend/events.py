"""Server-sent overview events backed by lightweight workspace revisions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
from typing import Callable, Iterator

from assessment.runtime import RUNS_ROOT, WORKSPACE


EVENT_INTERVAL_SECONDS = 1.0
KEEPALIVE_SECONDS = 15.0
JOB_STATE_ROOT = WORKSPACE / "worker" / ".state"


def _latest_mtime(paths: Iterator[Path]) -> int:
    latest = 0
    for path in paths:
        try:
            latest = max(latest, path.stat().st_mtime_ns)
        except OSError:
            continue
    return latest


def activity_revision() -> str:
    """Return a cheap revision for files that affect the live dashboard."""
    job_files = (
        path
        for pattern in ("jobs/*/job.json", "jobs/*/output.log", "wireless-devices.json")
        for path in JOB_STATE_ROOT.glob(pattern)
    )
    run_files = (
        path
        for pattern in (
            "*/report.json", "*/result.json", "*/codex-loop-result.json",
            "*/codex-loop-config.json", "*/native-selection.json",
        )
        for path in RUNS_ROOT.glob(pattern)
    )
    return f"{_latest_mtime(job_files):x}-{_latest_mtime(run_files):x}"


def overview_event_stream(snapshot: Callable[[], dict]) -> Iterator[str]:
    """Emit snapshots on state changes and comments while the stream is idle."""
    last_revision = ""
    last_digest = ""
    last_emission = 0.0
    while True:
        revision = activity_revision()
        now = time.monotonic()
        if not last_digest or revision != last_revision:
            payload = dict(snapshot())
            payload["revision"] = revision
            serialized = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            if digest != last_digest:
                yield f"id: {digest[:16]}\nevent: overview\ndata: {serialized}\n\n"
                last_digest = digest
                last_emission = now
            last_revision = revision
        elif now - last_emission >= KEEPALIVE_SECONDS:
            yield f": keepalive {int(time.time())}\n\n"
            last_emission = now
        time.sleep(EVENT_INTERVAL_SECONDS)

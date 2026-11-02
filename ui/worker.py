from __future__ import annotations

import os
import signal
import subprocess
import threading
import traceback
import uuid

from ui.job_queue import (
    atomic_write_json, claim_next_job, enqueue_due_usage_limit_jobs,
    read_json, recover_abandoned_jobs, touch_heartbeat, utc_now,
)
from ui.ghidra_proxy import GhidraLoopbackProxy
from ui.orchestrator import LoopRunner
from ui.orchestrator_runtime import EnvironmentFailure, LoopError


POLL_SECONDS = float(os.environ.get("MOB_AI_WORKER_POLL_SECONDS", "1"))


def execute(directory, state: dict, request: dict) -> None:
    payload = request.get("payload") or {}
    kind = str(state.get("kind") or request.get("kind") or "")
    exit_code = 1
    status = "error"
    run_dir = None
    with (directory / "output.log").open("a", encoding="utf-8", buffering=1) as log:
        log.write(f"\nDurable worker claimed job {state['id']} at {state['started_utc']}.\n")
        try:
            runner = LoopRunner(log)
            if kind == "resume":
                status, run_dir = runner.resume(payload)
            elif kind == "retry":
                status, run_dir = runner.retry_with_diagnostics(payload)
            elif kind == "start":
                status, run_dir = runner.new(payload)
            else:
                raise LoopError(f"Unsupported queued job kind: {kind!r}.")
            if not state.get("run_id"):
                state.update({
                    "run_id": run_dir.name,
                    "attempt_number": 1,
                    "attempt_kind": "initial",
                    "parent_job_id": "",
                })
            log.write(f"\nLoop finished: {status}\nRun directory: {run_dir}\n")
            exit_code = 0 if status in {"success", "success_without_bypass"} else 1
        except EnvironmentFailure as error:
            log.write(f"\nerror: {error}\n")
            status = "environment_error"
            exit_code = 2
        except (LoopError, ValueError) as error:
            log.write(f"\nerror: {error}\n")
            status = "needs_input"
            exit_code = 2
        except (OSError, subprocess.SubprocessError) as error:
            log.write(f"\nerror: {error}\n")
            status = "environment_error"
            exit_code = 2
        except Exception as error:  # keep the durable worker alive and preserve diagnostics
            log.write(f"\nunexpected worker error: {error}\n{traceback.format_exc()}\n")
            status = "worker_error"
            exit_code = 2
        finally:
            if status == "usage_limited" and run_dir is not None:
                summary = read_json(run_dir / "codex-loop-result.json")
                usage = summary.get("usage") or {}
                state.update({
                    "detail": str(summary.get("detail") or "Provider usage allowance exhausted."),
                    "auto_resume": bool(usage.get("auto_resume")),
                    "resume_after_utc": str(usage.get("reset_utc") or ""),
                    "usage_code": str(usage.get("code") or "usage_limit_exceeded"),
                })
            state.update({
                "running": False,
                "exit_code": exit_code,
                "status": status,
                "completed_utc": utc_now(),
            })
            atomic_write_json(directory / "job.json", state)


def main() -> int:
    worker_id = f"{os.uname().nodename}-{uuid.uuid4().hex[:8]}"
    stopping = threading.Event()
    ghidra_proxy = GhidraLoopbackProxy(
        os.environ.get("GHIDRA_MCP_URL", "http://reverse-engineering:8089")
    ).start()

    def stop(_signum, _frame) -> None:
        stopping.set()

    def heartbeat() -> None:
        while not stopping.is_set():
            touch_heartbeat(worker_id)
            stopping.wait(5)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    recover_abandoned_jobs()
    heartbeat_thread = threading.Thread(target=heartbeat, name="mob-ai-worker-heartbeat", daemon=True)
    heartbeat_thread.start()
    try:
        while not stopping.is_set():
            enqueue_due_usage_limit_jobs()
            claimed = claim_next_job(worker_id)
            if claimed:
                execute(*claimed)
                continue
            stopping.wait(POLL_SECONDS)
        touch_heartbeat(worker_id)
        return 0
    finally:
        ghidra_proxy.close()


if __name__ == "__main__":
    raise SystemExit(main())

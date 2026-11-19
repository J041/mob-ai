from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import threading
import traceback
import uuid

from worker.queue import (
    atomic_write_json, claim_next_job, enqueue_due_usage_limit_jobs,
    read_json, recover_abandoned_jobs, touch_heartbeat, utc_now,
)
from worker.ghidra_proxy import GhidraLoopbackProxy
from worker.job_types import JobType, job_type
from worker.job_timeline import JobProgressRecorder
from assessment.orchestrator import LoopRunner
from assessment.runtime import (
    EnvironmentFailure, JobCancelled, JobControl, JobPaused, LoopError,
    install_job_control,
)
from assessment.usage import aggregate_token_usage, assessment_token_usage, token_usage_delta
from assessment.deep_goal import run_deep_goal
from assessment.bypass_session import run_successful_bypass
from runtime_data import initialize_runtime_data
from backend.evidence_index import refresh_run_evidence_index


POLL_SECONDS = float(os.environ.get("MOB_AI_WORKER_POLL_SECONDS", "1"))


def dispatch_job(spec: JobType, runner: LoopRunner, payload: dict, log):
    """Bind registry executor identifiers to their runtime implementations."""
    executors = {
        "loop.new": lambda: runner.new(payload),
        "loop.resume": lambda: runner.resume(payload),
        "loop.retry_with_diagnostics": lambda: runner.retry_with_diagnostics(payload),
        "function.deep_goal": lambda: run_deep_goal(payload, log),
        "function.launch_bypass": lambda: run_successful_bypass(payload, log),
    }
    try:
        return executors[spec.executor]()
    except KeyError as error:
        raise LoopError(f"No worker executor is registered for {spec.name!r}.") from error


def execute(directory, state: dict, request: dict) -> None:
    payload = request.get("payload") or {}
    kind = str(state.get("kind") or request.get("kind") or "")
    spec = None
    exit_code = 1
    status = "error"
    run_dir = None
    requested_run = Path(str(payload.get("run") or "")) if payload.get("run") else None
    usage_before = (
        assessment_token_usage(requested_run)
        if requested_run is not None and requested_run.is_dir()
        else aggregate_token_usage([])
    )
    progress = JobProgressRecorder(
        directory / "progress.json", kind, str(state.get("queued_utc") or utc_now()),
    )
    JobProgressRecorder.initialize(
        directory / "progress.json", kind, str(state.get("queued_utc") or utc_now()),
    )
    progress.transition("starting")
    control = None
    index_requested = threading.Event()
    index_stopping = threading.Event()

    def record_stage(stage: str) -> None:
        progress.transition(stage)
        index_requested.set()

    control = JobControl(on_stage=record_stage)

    def update_evidence_index() -> None:
        while not index_stopping.is_set():
            if not index_requested.wait(0.5):
                continue
            index_requested.clear()
            current_run = control.run_dir
            if current_run is None or not current_run.is_dir():
                continue
            try:
                refresh_run_evidence_index(current_run)
            except (OSError, ValueError) as error:
                log.write(f"\nBackground evidence index refresh skipped: {error}\n")
    monitoring = threading.Event()

    def monitor_control() -> None:
        while not monitoring.wait(0.2):
            current = read_json(directory / "job.json")
            if current.get("cancel_requested"):
                control.request_cancel()
            if current.get("pause_requested"):
                control.request_pause()

    install_job_control(control)
    monitor = threading.Thread(target=monitor_control, name=f"job-control-{state['id'][:8]}", daemon=True)
    monitor.start()
    with (directory / "output.log").open("a", encoding="utf-8", buffering=1) as log:
        indexer = threading.Thread(
            target=update_evidence_index, name=f"evidence-index-{state['id'][:8]}", daemon=True,
        )
        indexer.start()
        log.write(f"\nDurable worker claimed job {state['id']} at {state['started_utc']}.\n")
        try:
            spec = job_type(kind)
            runner = LoopRunner(log)
            status, run_dir = dispatch_job(spec, runner, payload, log)
            if not state.get("run_id"):
                state.update({
                    "run_id": run_dir.name,
                    "attempt_number": 1,
                    "attempt_kind": "initial",
                    "parent_job_id": "",
                })
            log.write(f"\nLoop finished: {status}\nRun directory: {run_dir}\n")
            exit_code = 0 if spec.is_success(status) else 1
        except JobCancelled as error:
            log.write(f"\ncancelled: {error}\n")
            status = "cancelled"
            exit_code = None
            run_dir = control.run_dir
        except JobPaused as error:
            log.write(f"\npaused: {error}\n")
            status = "paused"
            exit_code = None
            run_dir = control.run_dir
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
            monitoring.set()
            monitor.join(timeout=1)
            index_stopping.set()
            index_requested.set()
            indexer.join()
            install_job_control(None)
            latest = read_json(directory / "job.json")
            state.update({
                key: value for key, value in latest.items()
                if key in {"cancel_requested", "cancel_requested_utc", "pause_requested", "pause_requested_utc"}
            })
            if run_dir is not None and not state.get("run_id"):
                state.update({
                    "run_id": run_dir.name,
                    "attempt_number": int(state.get("attempt_number") or 1),
                    "attempt_kind": str(state.get("attempt_kind") or "initial"),
                    "parent_job_id": str(state.get("parent_job_id") or ""),
                })
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
            progress.finish(status)
            if status in {"cancelled", "paused"}:
                state.update({
                    "detail": (
                        "Cancelled by the operator; completed evidence was preserved."
                        if status == "cancelled"
                        else "Paused after a safe stage; continue the assessment from its saved checkpoint."
                    ),
                    "checkpoint": {
                        "stage": control.stage,
                        "run_id": run_dir.name if run_dir is not None else "",
                    },
                })
            if run_dir is not None and run_dir.is_dir():
                try:
                    refresh_run_evidence_index(run_dir)
                except (OSError, ValueError) as error:
                    log.write(f"\nFinal evidence index refresh skipped: {error}\n")
                assessment_usage = assessment_token_usage(run_dir)
                state["token_usage"] = token_usage_delta(assessment_usage, usage_before)
                state["assessment_token_usage"] = assessment_usage
            atomic_write_json(directory / "job.json", state)


def main() -> int:
    initialize_runtime_data(migrate_legacy=True)
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

# Container tooling

JADX, Ghidra, and ADB are installed in the `reverse-engineering` Docker Compose service, not necessarily on the host.

When a task requires one of these tools, ensure the service is running and execute the command in it:

```powershell
docker compose up -d
docker compose exec -T reverse-engineering <command> <args...>
```

On Windows, `scripts\codex-container.cmd <command> <args...>` is a convenient build/start/exec wrapper that does not depend on PowerShell script execution policy.

The repository is mounted at `/workspace`, which is also the container working directory. Prefer headless commands (`jadx`, `analyzeHeadless`, and `adb`) so they work through Codex's terminal. Do not run untrusted samples outside the container.

## Authorized APK assessment pipeline

For an APK the user owns or is explicitly authorized to test, use `python3 pipeline/pipeline.py`. Start with the Frida strategy and review each run's `report.json` and logs before increasing the bypass level. Always pass the exact `--device` serial; never select or modify an unspecified device. Preserve `original.apk` and write changes only below that run directory.

Keep the default observation pass enabled unless the user explicitly requests otherwise. Review `observations.json` and `adaptive-plan.json`; prefer evidence-selected modules and preserve manually edited scripts. Use a structured `--success-spec` when reliable process, foreground-Activity, log, or Frida criteria are known, and report each failed criterion rather than treating process survival alone as proof of success.

For a user-requested autonomous run, prefer the Flask UI launched with `docker compose up -d --build --wait`; its Python orchestrator is `ui/orchestrator.py`. APKs arrive through the bounded `/api/apks` upload and Codex authenticates with persistent ChatGPT device-login state in the `codex-state` volume, not an API key. The loop is bounded and keeps each Codex repair phase isolated from device execution. Do not widen its file-write boundary, bypass its structured success policy, persist wireless pairing codes, or increase the default iteration limit without an explicit user request. Require the short-lived readiness token for a new UI run; it is bound to the exact target, transport and Frida path. Treat `human_review` and `assessment_failed` as terminal outcomes, not permission to rebuild the APK. A recognized Frida transport `human_review` and an `environment_error` with an observation or validation checkpoint may be recovered through the UI; archive failed evidence and do not repeat completed static analysis or Codex decisions. A `max_iterations` run may be continued only through the UI resume operation, which must preserve the recorded APK, success policy, target, prior candidate and append-only iteration history.

Prefer runtime hooks before static rebuilding. Static rebuilding requires a narrow, reviewed `--patch-script`; do not write broad or unrelated patches. Stop when the user's success marker is reached or after three iterations. Do not deploy generated artifacts outside the selected lab device.

For Android 11+ wireless debugging, the UI submits the six-digit code once to `/api/devices/pair`, which feeds it to `adb pair` over stdin and clears the browser field. The pairing and connection ports are normally different. Do not add pairing codes to files, command arguments, run state, or logs. For CLI use, prefer `scripts\codex-container-tty.cmd ...` for the hidden prompt or `MOB_AI_ADB_PAIRING_CODE` for unattended use. The connection endpoint becomes the exact selected device serial.

## Ghidra MCP

The project registers an optional `ghidra` MCP server through `.codex/config.toml`. Use it for interactive native-binary work such as importing suspicious `.so` files, enumerating functions and symbols, decompiling selected functions, and following cross-references. Prefer read-only inspection first. MCP write operations require approval; arbitrary Ghidra script execution is disabled.

The MCP backend is headless and limited to filesystem paths under `/workspace`. If MCP is unavailable in the current session, start the Compose service, open a new Codex session so project MCP configuration reloads, or fall back to `analyzeHeadless`.

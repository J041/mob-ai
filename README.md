# Mobile reverse-engineering toolbox

A non-root, three-image Docker stack containing:

- JADX 1.5.6 (`jadx` and `jadx-gui`)
- Ghidra 12.1.4 (`analyzeHeadless` and `ghidraRun`), aligned with Ghidra MCP 7.0.0
- the latest Android SDK Platform Tools at image build time (`adb`)
- Frida command-line tools, Apktool, and Uber APK Signer
- Codex CLI 0.162.1, Claude Code 2.1.316, Java 21, Python 3, Node.js 22.23.4 LTS, Git, and common file utilities

The repository is mounted at `/workspace`. `mob-ai-web` contains the Flask control plane, provider CLIs, ADB and Frida; `mob-ai-worker` adds Java, JADX, Apktool, signing and the Ghidra bridge; `mob-ai-ghidra` contains full Ghidra and its MCP server. The web and worker share common provider-runtime layers, while full Ghidra is not copied into either image. Ghidra user state and ADB keys live in named volumes, so rebuilding images does not discard them.

## One-command web application

The UI runs in a Flask/Gunicorn control service and assessments run in a separate
durable worker, not in PowerShell. No OpenAI API key is required. Launch the complete
stack with one command:

```powershell
docker compose up -d --build --wait
```

On Windows, `.\scripts\ui.cmd` is an equivalent one-command launcher. Open
`http://127.0.0.1:8787/`, then connect either **Codex · ChatGPT** or
**Claude · Claude.ai** from the dashboard. Each login persists in its own private
Docker volume (`codex-state` or `claude-state`). To use another port or change the upload limit, copy
`.env.example` to `.env` and edit it. Stop the application with `docker compose down`.

The dashboard provides:

- direct APK upload and success-policy selection;
- emulator, ADB serial, or wireless targets with in-UI pairing;
- device discovery through the lightweight web container;
- observation, runtime, Frida Server, and iteration controls;
- provider, model, and thinking-level selection for connected Codex and Claude accounts;
- durable queued start, resume, and diagnostic-retry jobs with live output;
- a run ledger showing findings, observations, status and resumability;
- a per-run artifact browser for findings, hooks, comparisons, crash logs, Codex decisions, saved Ghidra results, and success-policy checks;
- authorization confirmation before every start or resume operation.

Uploaded APKs are stored in the ignored `uploads/` directory and validated as APK/ZIP
files before a run starts. The default limit is 1024 MB. The host port binds only to
`127.0.0.1`. The Flask API validates paths under this
workspace, exposes fixed operations rather than arbitrary shell commands, and keeps
job requests and state under the ignored `ui/.state/` directory using atomic writes.
The dedicated worker claims queued jobs on disk, so restarting the web UI does not
interrupt an assessment. If the worker itself stops during device interaction, the
attempt is preserved as `interrupted` instead of silently repeating side effects.
The separate Ghidra service is reachable only on the private Compose network and
requires a bearer token. Wireless pairing
codes are submitted directly to `adb pair` over stdin, cleared from the form after
every attempt, and never stored in run configuration or job logs.

## Start and connect

From PowerShell:

```powershell
docker compose up -d --build
.\scripts\codex-container.cmd jadx --version
.\scripts\codex-container.cmd analyzeHeadless
.\scripts\codex-container.cmd adb version
```

Run `.\scripts\codex-container.cmd` with no arguments for an interactive worker shell. The wrapper routes `analyzeHeadless` and `ghidraRun` to the Ghidra image and all other commands to the worker image. Codex can use the same script; `AGENTS.md` records the direct Compose commands for future sessions. A PowerShell-native `codex-container.ps1` is also included, but Windows may require `powershell -ExecutionPolicy Bypass -File .\scripts\codex-container.ps1 ...` depending on local policy.

You can also open the folder as a Dev Container. The included `.devcontainer/devcontainer.json` attaches the editor—and a Codex terminal running there—to the same service.

## Examples

Decompile an APK into the mounted workspace:

```powershell
.\scripts\codex-container.cmd jadx -d /workspace/out /workspace/app.apk
```

Analyze a native binary with Ghidra in headless mode:

```powershell
.\scripts\codex-container.cmd analyzeHeadless /workspace/ghidra-projects sample -import /workspace/libnative.so
```

## Connecting ADB

For a device already listening over TCP/IP:

```powershell
.\scripts\codex-container.cmd adb connect 192.168.1.20:5555
.\scripts\codex-container.cmd adb devices -l
```

For Android 11 or newer wireless debugging, the pairing port and connection port shown on the phone are usually different. Enable **Developer options → Wireless debugging**, select **Pair device with pairing code**, and run:

```powershell
.\scripts\codex-container-tty.cmd python3 pipeline/pipeline.py /workspace/app.apk `
  --authorized --strategy frida `
  --wireless-pair 192.168.1.20:PAIRING_PORT `
  --wireless-connect 192.168.1.20:CONNECTION_PORT
```

The interactive wrapper permits a hidden six-digit-code prompt. The pipeline does not echo, log, or place that code in the process command line. It then connects the device, verifies its ADB state, and automatically uses `IP:CONNECTION_PORT` as the exact device serial. Pairing is normally needed only once because the existing `adb-keys` Docker volume persists the authorization. On subsequent runs, supply only `--wireless-connect` using the normal wrapper:

```powershell
.\scripts\codex-container.cmd python3 pipeline/pipeline.py /workspace/app.apk `
  --authorized --strategy frida `
  --wireless-connect 192.168.1.20:CONNECTION_PORT
```

For unattended operation, place the temporary code in `$env:MOB_AI_ADB_PAIRING_CODE` instead of command history. `--wireless-pair-code` is also supported but is less private. Clear the environment variable afterward.

Docker Desktop does not pass a Windows USB device directly into a Linux container. For a USB-connected device on Windows, use the host's ADB server and point the container client at it. Start the host server so it listens beyond loopback, then run:

```powershell
adb kill-server
adb -a nodaemon server start
# In another terminal:
.\scripts\codex-container.cmd adb -H host.docker.internal -P 5037 devices -l
```

`adb -a` exposes the server to the local network interfaces. Use it only on a trusted/firewalled machine, and stop it with `adb kill-server` after use. A network-connected device is usually the simpler option.

## Version overrides

The Compose build args can be overridden with environment variables. When changing Ghidra, also supply the SHA-256 published on its release page:

```powershell
$env:GHIDRA_VERSION = '12.2'
$env:GHIDRA_SHA256 = '<published sha256>'
$env:JADX_VERSION = '1.5.6'
docker compose build --no-cache
```

The current Ghidra archive is checksum-verified. JADX and Google's rolling Platform Tools archive are downloaded over HTTPS but are not checksum-pinned.

## Ghidra MCP for Codex

The Compose service starts a headless Ghidra MCP backend on the private Compose
network. It is not published to the host or LAN. The web service's Codex process
connects through the installed stdio bridge. Interactive host Codex sessions can
still use `scripts/ghidra-mcp.cmd` through the project `.codex/config.toml`.

Security defaults:

- filesystem operations are restricted to `/workspace`;
- arbitrary Ghidra script execution is disabled;
- the backend is unexposed to the host and requires `GHIDRA_MCP_AUTH_TOKEN`;
- MCP write tools require user approval in Codex;
- Ghidra MCP and its Python bridge are version-pinned and checksum-verified.

For unattended assessment reasoning, the worker exposes the private Compose backend
through a token-preserving loopback-only relay because the upstream MCP bridge accepts
only loopback server URLs. Trusted orchestration imports, analyzes, opens, and verifies
the selected programs before the provider starts. Provider sessions auto-connect through
that relay with strict program selectors and a bounded set of analysis groups; prompts
forbid connection, import, open, and other state-changing MCP tools.

Build, start, and verify the backend:

```powershell
docker compose up -d --build --wait
docker compose ps
```

Then start a new Codex session from this trusted project so `.codex/config.toml` is reloaded. Codex should expose a `ghidra` MCP server with tools for importing binaries, listing functions and symbols, decompiling functions, examining callers/callees, and following cross-references. If MCP is unavailable, the existing `analyzeHeadless` workflow remains usable.

The checked-in Codex configuration contains the absolute Windows workspace path for reliable process startup. Update the `args` entry in `.codex/config.toml` if the repository is moved.

## Authorized anti-root/anti-hooking assessment pipeline

The pipeline is for APKs you own or have explicit permission to test. It keeps the original read-only, records a SHA-256 and static findings, performs a non-mutating runtime observation pass, and generates up to three evidence-selected Frida hook iterations. All scripts, evidence and logs are stored in `runs/`. Frida is the default; static rebuilding requires a reviewed patch script.

Generate findings and Frida scripts without touching a device:

```powershell
.\scripts\codex-container.cmd python3 pipeline/pipeline.py /workspace/app.apk --authorized --strategy frida
```

Test on an emulator or physical device by passing its exact ADB serial. The device must already be authorized for ADB and must have a compatible `frida-server` available. This example optionally starts an already-installed server as root and installs the APK:

```powershell
.\scripts\codex-container.cmd python3 pipeline/pipeline.py /workspace/app.apk `
  --authorized --strategy frida --device SERIAL_FROM_ADB `
  --install --start-frida-server /data/local/tmp/frida-server `
  --success-regex 'EXPECTED_APP_READY_MARKER'
```

Observation mode defaults to `before`. It records suspicious Java and native calls without changing return values, writes `observations.json`, then selects only the matching bypass modules. Use `--observation-mode only` for discovery without bypassing, or `--observation-mode off` to generate hooks from static findings and any observations already stored in a resumed run. Adjust its window with `--observation-seconds`.

For stronger validation, copy `pipeline/success-spec.example.json`, edit it, and pass it instead of `--success-regex`:

```powershell
Copy-Item pipeline\success-spec.example.json success-spec.json
.\scripts\codex-container.cmd python3 pipeline/pipeline.py /workspace/app.apk `
  --authorized --strategy frida --device SERIAL_FROM_ADB --install `
  --success-spec /workspace/success-spec.json
```

A success specification has `mode: "all"` or `mode: "any"` and a non-empty `checks` array. Version 2 policies can also set `baseline_required`, `repeat`, and `min_passes`. Supported checks are:

- `process_alive`: the package has a PID after the observation window;
- `foreground_package`: the package (or an optional check-level `package`) is the resumed Activity;
- `activity_reached`: the resumed Activity contains the configured `activity` name;
- `no_crash`: logcat contains no fatal exception, process death, or force-finish marker;
- `ui_text_regex`: the current UIAutomator hierarchy matches `pattern`;
- `ui_text_not_regex`: the current UIAutomator hierarchy does not match `pattern`;
- `log_regex`: Android logcat matches `pattern`;
- `log_not_regex`: Android logcat does not match `pattern`;
- `frida_regex`: Frida output matches `pattern`;
- `output_regex`: combined Frida and logcat output matches `pattern`.

Every criterion and its result is stored under `attempts[].repetitions[].checks` in `result.json`. `--success-regex` remains available for simple and backward-compatible checks, but cannot be combined with `--success-spec`.

### Autonomous provider reasoning loop

The Python loop performs observation, asks the selected headless provider to make one narrowly
scoped candidate-hook change, validates it on the selected device, and feeds the
recorded failure into the next attempt. It stops when the success policy passes,
the provider requests human review, two attempts make no progress, or the iteration limit
is reached. The provider runs with only the current iteration directory writable; device
access and validation remain under the deterministic orchestrator.

Before the first hook decision, static preparation records a complete bounded inventory of
APK native libraries, including ABI, hash, size, and decompiled `loadLibrary` references,
and groups duplicate ABI variants under one logical library name.
The selected reasoning provider then performs a separate read-only native-triage pass and
chooses at most five logical libraries using Java/JNI load sites, application ownership, crash
evidence, protected startup, and runtime observations. Raw string matches cannot select a
library by themselves. The orchestrator extracts the variant matching the recorded device ABI.
The provider may request additional ABI variants only with an explicit comparison reason; those
variants remain part of the same logical selection slot. The validated result is stored in
`native-selection.json`; only those hash-verified libraries are extracted under `native/selected/` and offered to the Ghidra
specialist. If Ghidra has no open instance, the iteration prompt requires the specialist to
import or open a selected binary rather than treating an empty instance list as analysis.

Before each reasoning iteration, the deterministic orchestrator copies every active primary and
approved cross-ABI binary to a hash-qualified run input, imports it through the private Ghidra
backend into an isolated run/batch/hash project folder, starts auto-analysis, and polls until the
bounded analysis completes. Results, program names, hashes, function counts, partial failures, and
timeouts are checkpointed at `ghidra/preparation/batch-N.json`. Completed manifests are reused on
retry so the provider receives already-analyzed programs and does not duplicate imports.

For larger APKs, native triage maintains a persisted queue of at most fifteen logical libraries
in batches of five. Only the active batch is extracted and authorized for an iteration. When its
validation remains unsuccessful, the batch is recorded as inconclusive and the next batch is
activated. Successful validation resolves the queue; retries and max-iteration resumes preserve
the active batch and append-only batch history rather than restarting native triage. Assessment
rows show the current batch and processed/total library counts.

When fewer than five targets remain queued and the fifteen-library lifetime budget still has
room, the provider performs a read-only replenishment decision after an inconclusive batch. It
may append previously unseen logical libraries using the completed iteration and Ghidra evidence;
duplicates, already processed targets, unavailable names, and additions beyond the remaining
budget are rejected deterministically. Replenishment prompts, decisions, errors, and additions
are retained below `agent/native-selection/replenishment-N/` and in `native-selection.json`.

Prerequisites are Docker Desktop, a connected ChatGPT or Claude account, an
authorized test device, and a compatible running or startable Frida Server. The UI
builds an auditable policy from **Basic launch**, **Detection warning removed**,
**Expected screen reached**, or **Custom** presets. It records the no-bypass baseline
and can require the same candidate to pass up to three repeated validations. Advanced
users can still select an existing JSON policy.

Open the web UI, upload the APK, select the policy, choose the emulator/physical target, confirm
authorization, and press **Start assessment**. For wireless debugging, select
**Wireless**, enter the pairing address and six-digit code shown by Android, and press
**Pair device**. Then enter the separate `IP:CONNECTION_PORT` from the main Wireless
debugging screen before starting the assessment. Pairing is normally required only once.

Before **Start assessment** is enabled, run **Device readiness** for the exact target. The wizard checks ADB state, root access, ABI, Android SDK, temporary storage, SELinux, Frida client/server versions, port forwarding and Frida connectivity. You may optionally select a trusted Frida Server binary to push to the configured device path and start it. A successful check issues a ten-minute token bound to the target, transport and Frida path; changing any of those values requires another check. Pairing codes are never included in readiness state.

The Wireless section also keeps a local, non-secret registry of successful pairings
under `ui/.state/`. It combines that history with `adb devices` and ADB mDNS discovery
to distinguish **Connected**, **Previously paired**, **Discovered**, **Unauthorized**,
and **Offline** devices. Pairing and last-used connection endpoints and timestamps may
be retained; six-digit pairing codes are never stored. A previously paired label is
host history rather than proof that Android has not subsequently revoked the pairing.

**Reasoning mode** controls each provider iteration. **Single agent** disables delegation. **Parallel specialists** allows two or three read-only reviewers to inspect independent static, runtime, and relevant native evidence when supported by the selected provider. Specialists cannot edit the hook or operate the device; only the root agent may update `candidate.js` and return the structured decision.

Native triage is auditable under append-only `runs/RUN_ID/agent/native-selection/attempt-N/` directories, with its final validated selection at `runs/RUN_ID/native-selection.json`. Each hook iteration is auditable under `runs/RUN_ID/agent/iteration-N/` and contains the prompt, candidate hook, provider decision and log, Frida/logcat output, validation result, and combined record. `codex-loop-result.json` retains its compatibility filename and records the terminal status and complete history. The loop never rebuilds or resigns the APK, and it directs the provider to request human review for remote attestation or unsupported/high-risk changes.

Reasoning execution is normalized in `ui/providers.py`. CLI providers receive the same
prompt, JSON schema, model/effort selection, working directory, and access mode, then
return the same validated JSON object. This is the extension point for a future
self-hosted adapter: add its transport and authentication/model catalog while preserving
schema validation, the candidate-only write boundary, and deterministic device validation.

Each assessment row also exposes **Ask assistant**. The run assistant operates in a
read-only sandbox and answers questions from that run's recorded artifacts, with
clickable citations into the Artifact browser. It ranks evidence for each question
and sends a bounded snapshot rather than the complete run, while the drawer reports
the current evidence-selection, reasoning, and validation stage. A request such as “try harder” may
produce a bounded rerun proposal, but it cannot operate the device or queue work
directly. **Review in Continue / retry** copies the proposal into the normal durable
job form, where authorization must be confirmed before submission. Conversation
turns and assistant logs are append-only under `runs/RUN_ID/assistant/`.

If a run ends with `max_iterations`, select it in the UI and resume it. The iteration
count is the number of **additional** attempts. The next iteration is seeded from the
last validated candidate, prior records remain append-only, and numbering continues.
The recorded device, package, success specification, run window, and Frida Server
path are reused. A different Codex model may be selected for the additional attempts.

Provider allowance exhaustion is recorded separately as `usage_limited`, not as a
generic provider failure. Mob-AI preserves the provider log and a trusted snapshot of
the candidate from before the interrupted reasoning turn. **Resume after reset**
restarts that same incomplete iteration without repeating observation, static analysis,
or Ghidra preparation. New and continuation forms can opt into automatic resume, but
the worker schedules it only when the provider returned an explicit reset timestamp;
an unknown reset time always requires manual continuation. A later manual attempt
supersedes any older automatic checkpoint so it cannot launch a duplicate job.

The **Continue / retry** panel displays the success policy bound to the selected
assessment, including its checks, repeat threshold, and baseline requirement. The
policy is hash-verified and cannot be changed during continuation; start a new
assessment when the success criteria themselves need to change.

Select an assessment under **Continue / retry**, then use **Reassess with a different
policy** to create that new assessment without uploading the APK again. The form
copies the prior target and policy as editable starting values, requires a fresh
device-readiness check, and records the new run's `derived_from_run` and prior policy
hash. When the APK hash matches, JADX and native static artifacts are copied from the
source run; observation and every success-policy validation are always rerun from
scratch.

Resume validates the original APK hash, success-policy hash, previous candidate hash, target transport and target identity. It refuses successful, non-recoverable `human_review`, `no_progress`, corrupted, or operational-error runs. You may supply `-Apk`, `-SuccessSpec`, `-Device`, or `-WirelessConnect` again for clarity, but their identities must match the recorded run. A changed success policy starts a new assessment rather than silently changing the old run's goalposts.

A `human_review` run caused specifically by a recognized Frida connection or server-path failure exposes **Fix Frida** in the run ledger. Select it, enter the corrected device-side Frida Server path, and continue. The orchestrator archives the failed observation under `agent/checkpoint-recovery-N/`, verifies the recorded APK, policy, and target, reruns observation in the same run, and invokes the next Codex iteration only if the baseline still fails. Other `human_review` outcomes remain terminal.

Operational ADB, Frida or device failures use `environment_error`, not `human_review`. When the failure occurred during observation or candidate validation, the run exposes **Recover** and records the exact checkpoint in `codex-loop-result.json`. Observation recovery keeps JADX output; validation recovery reuses the already-reviewed candidate and Codex decision. `needs_input` identifies missing or incompatible user configuration, while `assessment_failed` means validation completed but the structured policy remained unsatisfied with no justified progress. Genuine evidence or protection ambiguity remains `human_review`.

Every non-success terminal summary also contains a structured `terminal` outcome with
a stable cause code, operator-facing label, explanation, recommended action, and
diagnostic-round usage. The dashboard derives the same structure for older runs
without modifying their evidence. This distinguishes causes such as unavailable
protected payloads, instrumentation perturbation, insufficient causal evidence,
possible remote attestation, provider failures, and device/tool failures while
preserving the compatible top-level status.

For a wireless physical device, replace `--device SERIAL_FROM_ADB` with `--wireless-connect IP:CONNECTION_PORT`; add `--wireless-pair IP:PAIRING_PORT` on the first connection. The same installation, Frida forwarding, logging, and success checks then apply.

If `frida-server` is already running, omit `--start-frida-server`. The pipeline forwards that device's port 27042 and connects through `127.0.0.1:27042`. For a remote server, use `--frida-endpoint HOST:PORT`.

Each run contains:

- `report.json`: source hash, detected package, and evidence locations
- `native/`: only native libraries containing suspicious indicators, ready for Ghidra
- `observations.json`: runtime API observations and abbreviated Java/native call stacks
- `adaptive-plan.json`: evidence-selected modules and the exact script hash for each iteration
- `frida/observe.js`: observation-only runtime instrumentation
- `frida/bypass-level-1.js`: Java root/debug checks
- `frida/bypass-level-2.js`: adds native filesystem checks
- `frida/bypass-level-3.js`: adds narrowly scoped anti-Frida string checks
- `logs/`: JADX, Frida, and logcat output for every attempt
- `result.json`: selected device, package, and success-marker result
- `agent/iteration-N/`: isolated Codex candidate, structured decision, validation and logs
- `codex-loop-config.json`: immutable run identity and compatibility values used for resume
- `codex-loop-result.json`: autonomous-loop terminal status and audit history

Review and edit a generated hook, then run it directly when an app-specific detector needs a targeted change:

```powershell
.\scripts\codex-container.cmd frida -H 127.0.0.1:27042 -f com.example.app `
  -l /workspace/runs/RUN_ID/frida/bypass-level-1.js
```

Generated scripts are automatically regenerated when new observations change the adaptive plan. Once a generated script is manually edited, its hash no longer matches the plan and the pipeline preserves it on resume so Codex can safely refine app-specific hooks. Suspicious native libraries can be investigated with Ghidra MCP or `analyzeHeadless` from the same run directory.

To choose interactively between Frida and rebuilding, use `--strategy choose`. Static rebuilding deliberately pauses after decoding and creates `patch.py`; review or replace it, then resume:

```powershell
.\scripts\codex-container.cmd python3 pipeline/pipeline.py --authorized `
  --strategy rebuild --resume /workspace/runs/RUN_ID `
  --patch-script /workspace/runs/RUN_ID/patch.py
```

The rebuilt test APK is signed with a generated debug key and will not retain the original publisher signature. Apps using signature checks or Play Integrity may therefore behave differently.

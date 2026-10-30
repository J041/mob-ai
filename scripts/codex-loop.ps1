[CmdletBinding()]
param(
    [string]$Apk,

    [string]$Resume,

    [string]$Device,
    [string]$WirelessConnect,

    [string]$SuccessSpec,

    [ValidateRange(1, 10)]
    [int]$MaxIterations = 3,

    [ValidateRange(1, 600)]
    [int]$ObservationSeconds = 15,

    [ValidateRange(1, 600)]
    [int]$RunSeconds = 20,

    [switch]$Install,
    [string]$StartFridaServer,
    [string]$Package,
    [string]$Model
)

$ErrorActionPreference = "Stop"
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$Workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Schema = Join-Path $Workspace "pipeline\codex-decision.schema.json"

function Convert-ToWorkspacePath {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$RequireFile)
    $Resolved = (Resolve-Path $Path).Path
    $Prefix = $Workspace.TrimEnd('\') + '\'
    if (-not $Resolved.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path must be inside the workspace: $Resolved"
    }
    if ($RequireFile -and -not (Test-Path -LiteralPath $Resolved -PathType Leaf)) {
        throw "File does not exist: $Resolved"
    }
    $Relative = $Resolved.Substring($Prefix.Length).Replace('\', '/')
    return "/workspace/$Relative"
}

function Convert-FromWorkspacePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not $Path.StartsWith('/workspace/')) {
        throw "Unexpected container run path: $Path"
    }
    return Join-Path $Workspace $Path.Substring('/workspace/'.Length).Replace('/', '\')
}

function Get-RelativeWorkspacePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $Resolved = [System.IO.Path]::GetFullPath($Path)
    $Prefix = $Workspace.TrimEnd('\') + '\'
    if (-not $Resolved.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Artifact escaped the workspace: $Resolved"
    }
    return $Resolved.Substring($Prefix.Length).Replace('\', '/')
}

function Invoke-Pipeline {
    param(
        [Parameter(Mandatory = $true)][string[]]$PipelineArguments,
        [Parameter(Mandatory = $true)][string]$LogPath
    )
    $Output = @(& docker compose exec -T reverse-engineering python3 pipeline/pipeline.py @PipelineArguments 2>&1)
    $ExitCode = $LASTEXITCODE
    $Output | Set-Content -LiteralPath $LogPath -Encoding UTF8
    $Output | ForEach-Object { Write-Host $_ }
    return [ordered]@{ ExitCode = $ExitCode; Text = ($Output -join "`n") }
}

function Add-TargetArguments {
    param([System.Collections.Generic.List[string]]$Arguments)
    if ($Device) {
        $Arguments.Add('--device')
        $Arguments.Add($Device)
    } else {
        $Arguments.Add('--wireless-connect')
        $Arguments.Add($WirelessConnect)
    }
    if ($Package) {
        $Arguments.Add('--package')
        $Arguments.Add($Package)
    }
}

function Write-LoopSummary {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$RunDirectory,
        [Parameter(Mandatory = $true)][object[]]$Records,
        [string]$Detail = ""
    )
    $Summary = [ordered]@{
        status = $Status
        detail = $Detail
        run_directory = Get-RelativeWorkspacePath $RunDirectory
        completed_utc = [DateTime]::UtcNow.ToString('o')
        iterations = $Records
    }
    $SummaryPath = Join-Path $RunDirectory 'codex-loop-result.json'
    $Summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
    Write-Host "Codex loop status: $Status"
    Write-Host "Audit summary: $SummaryPath"
}

function Get-AttemptFingerprint {
    param(
        [Parameter(Mandatory = $true)][string]$CandidateHash,
        [Parameter(Mandatory = $true)][object]$Validation
    )
    $ValidationCompact = $Validation | ConvertTo-Json -Depth 20 -Compress
    $FingerprintBytes = [Text.Encoding]::UTF8.GetBytes($CandidateHash.ToLowerInvariant() + $ValidationCompact)
    $Hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($Hasher.ComputeHash($FingerprintBytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $Hasher.Dispose()
    }
}

$IsResume = -not [string]::IsNullOrWhiteSpace($Resume)
if ($IsResume -and $Install) {
    throw "-Install cannot be combined with -Resume; resume preserves the installed-app state from the original run."
}
if (-not $IsResume -and [string]::IsNullOrWhiteSpace($Apk)) {
    throw "Supply -Apk for a new run, or -Resume for an existing run."
}
if (-not $IsResume -and [string]::IsNullOrWhiteSpace($SuccessSpec)) {
    throw "Supply -SuccessSpec for a new run."
}
if ($Device -and $WirelessConnect) {
    throw "Supply either -Device or -WirelessConnect, not both."
}
if (-not $IsResume -and -not $Device -and -not $WirelessConnect) {
    throw "Supply -Device or an already-paired -WirelessConnect endpoint. Pair wireless devices before starting the autonomous loop."
}

$Codex = (Get-Command codex -ErrorAction Stop).Source

Push-Location $Workspace
try {
    & docker compose up -d --build --wait
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose failed to start the toolbox."
    }

    if ($IsResume) {
        $RunDirectory = (Resolve-Path $Resume).Path
        $RunRelative = Get-RelativeWorkspacePath $RunDirectory
        $RunContainer = "/workspace/$RunRelative"
        $AgentDirectory = Join-Path $RunDirectory 'agent'
        $ConfigPath = Join-Path $RunDirectory 'codex-loop-config.json'
        $SummaryPath = Join-Path $RunDirectory 'codex-loop-result.json'
        foreach ($RequiredPath in @($AgentDirectory, $ConfigPath, $SummaryPath, (Join-Path $RunDirectory 'report.json'), (Join-Path $RunDirectory 'original.apk'))) {
            if (-not (Test-Path -LiteralPath $RequiredPath)) {
                throw "Cannot resume: required run artifact is missing: $RequiredPath"
            }
        }

        $LoopConfig = Get-Content -Raw $ConfigPath | ConvertFrom-Json
        $PriorSummary = Get-Content -Raw $SummaryPath | ConvertFrom-Json
        if ([int]$LoopConfig.version -ne 1) {
            throw "Cannot resume unsupported loop configuration version $($LoopConfig.version)."
        }
        if ($PriorSummary.status -ne 'max_iterations') {
            throw "Only a run stopped by max_iterations can be resumed; this run ended with '$($PriorSummary.status)'."
        }
        $OriginalHash = (Get-FileHash -LiteralPath (Join-Path $RunDirectory 'original.apk') -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($OriginalHash -ne [string]$LoopConfig.apk_sha256) {
            throw "Cannot resume because original.apk no longer matches the recorded APK hash."
        }
        if ($Apk) {
            $SuppliedApkHash = (Get-FileHash -LiteralPath (Resolve-Path $Apk).Path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($SuppliedApkHash -ne [string]$LoopConfig.apk_sha256) {
                throw "The supplied -Apk does not match the APK recorded for this run."
            }
        }

        if ($SuccessSpec) {
            $SuccessSpecHost = (Resolve-Path $SuccessSpec).Path
        } else {
            $SuccessSpecHost = Join-Path $Workspace ([string]$LoopConfig.success_spec).Replace('/', '\')
        }
        if (-not (Test-Path -LiteralPath $SuccessSpecHost -PathType Leaf)) {
            throw "The recorded success specification is unavailable; pass -SuccessSpec with the same file contents."
        }
        $SuccessSpecHash = (Get-FileHash -LiteralPath $SuccessSpecHost -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($SuccessSpecHash -ne [string]$LoopConfig.success_spec_sha256) {
            throw "Cannot resume with a changed success policy. Its SHA-256 does not match the original run."
        }
        $SuccessSpecContainer = Convert-ToWorkspacePath -Path $SuccessSpecHost -RequireFile

        if ($LoopConfig.transport -eq 'wireless') {
            if ($Device) { throw "This run used wireless transport; resume it with -WirelessConnect or omit the target to reuse the recorded endpoint." }
            if ($WirelessConnect -and $WirelessConnect -ne $LoopConfig.target) { throw "-WirelessConnect does not match the recorded target $($LoopConfig.target)." }
            $WirelessConnect = [string]$LoopConfig.target
        } else {
            if ($WirelessConnect) { throw "This run used an ADB serial; resume it with -Device or omit the target to reuse the recorded serial." }
            if ($Device -and $Device -ne $LoopConfig.target) { throw "-Device does not match the recorded target $($LoopConfig.target)." }
            $Device = [string]$LoopConfig.target
        }
        if ($Package -and $Package -ne $LoopConfig.package) {
            throw "-Package does not match the package recorded for this run."
        }
        $Package = [string]$LoopConfig.package
        if ($PSBoundParameters.ContainsKey('RunSeconds') -and $RunSeconds -ne [int]$LoopConfig.run_seconds) {
            throw "-RunSeconds must match the recorded value $($LoopConfig.run_seconds) when resuming."
        }
        $RunSeconds = [int]$LoopConfig.run_seconds
        if ($PSBoundParameters.ContainsKey('StartFridaServer') -and $StartFridaServer -ne [string]$LoopConfig.start_frida_server) {
            throw "-StartFridaServer must match the path recorded by the original run."
        }
        $StartFridaServer = [string]$LoopConfig.start_frida_server
        if (-not $PSBoundParameters.ContainsKey('Model') -and $LoopConfig.model) { $Model = [string]$LoopConfig.model }

        $Records = @($PriorSummary.iterations)
        if ($Records.Count -lt 1) {
            throw "Cannot resume because the prior run has no completed iteration records."
        }
        $LastRecord = $Records | Sort-Object { [int]$_.iteration } | Select-Object -Last 1
        $LastIteration = [int]$LastRecord.iteration
        $PreviousCandidate = Join-Path $Workspace ([string]$LastRecord.candidate).Replace('/', '\')
        $RunPrefix = [System.IO.Path]::GetFullPath($RunDirectory).TrimEnd('\') + '\'
        if (-not [System.IO.Path]::GetFullPath($PreviousCandidate).StartsWith($RunPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Cannot resume because the recorded candidate is outside the selected run directory."
        }
        if (-not (Test-Path -LiteralPath $PreviousCandidate -PathType Leaf)) {
            throw "Cannot resume because the last candidate is missing: $PreviousCandidate"
        }
        $ActualCandidateHash = (Get-FileHash -LiteralPath $PreviousCandidate -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ActualCandidateHash -ne [string]$LastRecord.candidate_sha256) {
            throw "Cannot resume because the last candidate was modified after validation."
        }
        $PreviousFingerprint = Get-AttemptFingerprint -CandidateHash $ActualCandidateHash -Validation $LastRecord.validation
        $StartIteration = $LastIteration + 1
        $EndIteration = $StartIteration + $MaxIterations - 1
        $StartServerOnNextAttempt = -not [string]::IsNullOrWhiteSpace($StartFridaServer)
        Write-Host "Resuming $RunRelative at iteration $StartIteration for up to $MaxIterations additional attempts."
    } else {
        $ApkContainer = Convert-ToWorkspacePath -Path $Apk -RequireFile
        $SuccessSpecContainer = Convert-ToWorkspacePath -Path $SuccessSpec -RequireFile
        $BootstrapLog = Join-Path $Workspace ('.codex-loop-bootstrap-{0}.log' -f [Guid]::NewGuid().ToString('N'))
        $Initial = [System.Collections.Generic.List[string]]::new()
        $Initial.Add($ApkContainer)
        $Initial.Add('--authorized')
        $Initial.Add('--strategy')
        $Initial.Add('frida')
        $Initial.Add('--observation-mode')
        $Initial.Add('only')
        $Initial.Add('--observation-seconds')
        $Initial.Add([string]$ObservationSeconds)
        $Initial.Add('--run-seconds')
        $Initial.Add([string]$RunSeconds)
        $Initial.Add('--success-spec')
        $Initial.Add($SuccessSpecContainer)
        Add-TargetArguments $Initial
        if ($Install) { $Initial.Add('--install') }
        if ($StartFridaServer) {
            $Initial.Add('--start-frida-server')
            $Initial.Add($StartFridaServer)
        }

        $Bootstrap = Invoke-Pipeline -PipelineArguments $Initial.ToArray() -LogPath $BootstrapLog
        if ($Bootstrap.ExitCode -notin @(0, 1)) {
            throw "Initial observation failed with exit code $($Bootstrap.ExitCode). See $BootstrapLog"
        }
        $RunMatch = [regex]::Match($Bootstrap.Text, 'Run directory:\s+(?<path>/workspace/\S+)')
        if (-not $RunMatch.Success) {
            throw "The pipeline did not report its run directory. See $BootstrapLog"
        }

        $RunContainer = $RunMatch.Groups['path'].Value.Trim()
        $RunDirectory = Convert-FromWorkspacePath $RunContainer
        $AgentDirectory = Join-Path $RunDirectory 'agent'
        New-Item -ItemType Directory -Path $AgentDirectory -Force | Out-Null
        Move-Item -LiteralPath $BootstrapLog -Destination (Join-Path $AgentDirectory 'bootstrap.log') -Force

        $InitialResultPath = Join-Path $RunDirectory 'result.json'
        if (-not (Test-Path -LiteralPath $InitialResultPath -PathType Leaf)) {
            throw "The observation phase did not produce result.json. See $(Join-Path $AgentDirectory 'bootstrap.log')"
        }
        $InitialResult = Get-Content -Raw $InitialResultPath | ConvertFrom-Json
        $Report = Get-Content -Raw (Join-Path $RunDirectory 'report.json') | ConvertFrom-Json
        $DetectedPackage = [string]$InitialResult.package
        $LoopConfig = [ordered]@{
            version = 1
            apk = (Get-RelativeWorkspacePath -Path (Resolve-Path $Apk).Path)
            apk_sha256 = ([string]$Report.sha256).ToLowerInvariant()
            success_spec = (Get-RelativeWorkspacePath -Path (Resolve-Path $SuccessSpec).Path)
            success_spec_sha256 = (Get-FileHash -LiteralPath (Resolve-Path $SuccessSpec).Path -Algorithm SHA256).Hash.ToLowerInvariant()
            transport = if ($WirelessConnect) { 'wireless' } else { 'adb' }
            target = if ($WirelessConnect) { $WirelessConnect } else { $Device }
            package = $DetectedPackage
            observation_seconds = $ObservationSeconds
            run_seconds = $RunSeconds
            start_frida_server = $StartFridaServer
            model = $Model
            created_utc = [DateTime]::UtcNow.ToString('o')
        }
        $LoopConfig | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $RunDirectory 'codex-loop-config.json') -Encoding UTF8
        $Package = $DetectedPackage
        $Records = @()
        if ($InitialResult.success) {
            Write-LoopSummary -Status 'success_without_bypass' -RunDirectory $RunDirectory -Records $Records -Detail 'The observation run already satisfied the success policy.'
            exit 0
        }

        $PreviousCandidate = $null
        $PreviousFingerprint = $null
        $StartIteration = 1
        $EndIteration = $MaxIterations
        $StartServerOnNextAttempt = $false
    }

    for ($Iteration = $StartIteration; $Iteration -le $EndIteration; $Iteration++) {
        $IterationDirectory = Join-Path $AgentDirectory ("iteration-{0}" -f $Iteration)
        if (Test-Path -LiteralPath $IterationDirectory) {
            throw "Refusing to overwrite existing iteration directory: $IterationDirectory"
        }
        New-Item -ItemType Directory -Path $IterationDirectory -Force | Out-Null
        $IterationCodexDirectory = Join-Path $IterationDirectory '.codex'
        New-Item -ItemType Directory -Path $IterationCodexDirectory -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $Workspace '.codex\config.toml') -Destination (Join-Path $IterationCodexDirectory 'config.toml') -Force
        $Candidate = Join-Path $IterationDirectory 'candidate.js'
        if ($PreviousCandidate) {
            Copy-Item -LiteralPath $PreviousCandidate -Destination $Candidate
        } else {
            $SeedLevel = [Math]::Min($Iteration, 3)
            $Seed = Join-Path $RunDirectory ("frida\bypass-level-{0}.js" -f $SeedLevel)
            Copy-Item -LiteralPath $Seed -Destination $Candidate
        }

        $CandidateRelative = Get-RelativeWorkspacePath $Candidate
        $PriorDirectory = if ($Iteration -gt 1) { Join-Path $AgentDirectory ("iteration-{0}" -f ($Iteration - 1)) } else { 'none' }
        $Prompt = @"
You are the reasoning step in an explicitly authorized Android application assessment loop.

Iteration: $Iteration (this invocation covers $StartIteration through $EndIteration)
Read-only run evidence directory: $RunDirectory
Editable candidate hook: $Candidate
Previous iteration evidence: $PriorDirectory
Ghidra MCP container path prefix for this run: $RunContainer

Goal: make the smallest evidence-based change to the candidate Frida hook that can satisfy the success policy. Inspect report.json, observations.json, adaptive-plan.json, the JADX output, and prior Frida/logcat/validation records. If native evidence is relevant, use the read-only Ghidra MCP tools to inspect only native libraries from this run.

Hard boundaries:
- Edit only $Candidate. Do not modify the APK, pipeline, success policy, reports, logs, or any other file.
- Do not run Docker, ADB, Frida, the pipeline, install commands, or interact with a device. The deterministic orchestrator performs validation after you return.
- Do not rebuild or resign the APK.
- Keep hooks narrowly tied to observed anti-root, anti-debugging, or anti-hooking behavior. Do not disable unrelated security controls.
- If evidence is insufficient, the next change would be speculative/high-risk, or success requires defeating remote attestation such as Play Integrity, return human_review without editing.
- Never claim success; only the structured success policy can establish it.

Return the required structured decision after inspecting and, when justified, editing the candidate.
"@
        $PromptPath = Join-Path $IterationDirectory 'prompt.txt'
        $DecisionPath = Join-Path $IterationDirectory 'decision.json'
        $CodexLog = Join-Path $IterationDirectory 'codex.log'
        $Prompt | Set-Content -LiteralPath $PromptPath -Encoding UTF8
        $ConfigPath = Join-Path $IterationCodexDirectory 'config.toml'
        $PromptHashBefore = (Get-FileHash -LiteralPath $PromptPath -Algorithm SHA256).Hash
        $ConfigHashBefore = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash

        $CodexArguments = [System.Collections.Generic.List[string]]::new()
        $CodexArguments.Add('exec')
        $CodexArguments.Add('--sandbox')
        $CodexArguments.Add('workspace-write')
        $CodexArguments.Add('--cd')
        $CodexArguments.Add($IterationDirectory)
        $CodexArguments.Add('--skip-git-repo-check')
        $CodexArguments.Add('--ephemeral')
        $CodexArguments.Add('--color')
        $CodexArguments.Add('never')
        $CodexArguments.Add('--config')
        $CodexArguments.Add('approval_policy="never"')
        $CodexArguments.Add('--output-schema')
        $CodexArguments.Add($Schema)
        $CodexArguments.Add('--output-last-message')
        $CodexArguments.Add($DecisionPath)
        if ($Model) {
            $CodexArguments.Add('--model')
            $CodexArguments.Add($Model)
        }
        $CodexArguments.Add('-')

        $CodexArgumentArray = $CodexArguments.ToArray()
        $CodexOutput = @($Prompt | & $Codex @CodexArgumentArray 2>&1)
        $CodexExit = $LASTEXITCODE
        $CodexOutput | Set-Content -LiteralPath $CodexLog -Encoding UTF8
        if ($CodexExit -ne 0 -or -not (Test-Path -LiteralPath $DecisionPath)) {
            Write-LoopSummary -Status 'codex_error' -RunDirectory $RunDirectory -Records $Records -Detail "Codex failed in iteration $Iteration. See $CodexLog"
            exit 2
        }
        $PromptHashAfter = (Get-FileHash -LiteralPath $PromptPath -Algorithm SHA256).Hash
        $ConfigHashAfter = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
        $AllowedFiles = @($Candidate, $PromptPath, $DecisionPath, $CodexLog, $ConfigPath) | ForEach-Object { [System.IO.Path]::GetFullPath($_) }
        $UnexpectedFiles = @(Get-ChildItem -LiteralPath $IterationDirectory -Recurse -File | Where-Object {
            $FullName = [System.IO.Path]::GetFullPath($_.FullName)
            -not ($AllowedFiles | Where-Object { $_.Equals($FullName, [System.StringComparison]::OrdinalIgnoreCase) })
        })
        if ($PromptHashBefore -ne $PromptHashAfter -or $ConfigHashBefore -ne $ConfigHashAfter -or $UnexpectedFiles.Count -gt 0) {
            Write-LoopSummary -Status 'codex_boundary_error' -RunDirectory $RunDirectory -Records $Records -Detail "Codex wrote outside the candidate hook boundary in iteration $Iteration."
            exit 2
        }

        $Decision = Get-Content -Raw $DecisionPath | ConvertFrom-Json
        if ($Decision.decision -eq 'human_review') {
            $Record = [ordered]@{ iteration = $Iteration; codex = $Decision; validation = $null }
            $Records += $Record
            $Record | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $IterationDirectory 'record.json') -Encoding UTF8
            Write-LoopSummary -Status 'human_review' -RunDirectory $RunDirectory -Records $Records -Detail $Decision.rationale
            exit 3
        }

        $CandidateContainer = "$RunContainer/agent/iteration-$Iteration/candidate.js"
        $AttemptArguments = [System.Collections.Generic.List[string]]::new()
        $AttemptArguments.Add('--authorized')
        $AttemptArguments.Add('--strategy')
        $AttemptArguments.Add('frida')
        $AttemptArguments.Add('--resume')
        $AttemptArguments.Add($RunContainer)
        $AttemptArguments.Add('--observation-mode')
        $AttemptArguments.Add('off')
        $AttemptArguments.Add('--candidate-script')
        $AttemptArguments.Add($CandidateContainer)
        $AttemptArguments.Add('--run-seconds')
        $AttemptArguments.Add([string]$RunSeconds)
        $AttemptArguments.Add('--success-spec')
        $AttemptArguments.Add($SuccessSpecContainer)
        Add-TargetArguments $AttemptArguments
        if ($StartServerOnNextAttempt -and $Iteration -eq $StartIteration) {
            $AttemptArguments.Add('--start-frida-server')
            $AttemptArguments.Add($StartFridaServer)
        }

        $PipelineLog = Join-Path $IterationDirectory 'pipeline.log'
        $ActiveResultPath = Join-Path $RunDirectory 'result.json'
        if (Test-Path -LiteralPath $ActiveResultPath -PathType Leaf) {
            Move-Item -LiteralPath $ActiveResultPath -Destination (Join-Path $IterationDirectory 'pre-validation-result.json') -Force
        }
        $Attempt = Invoke-Pipeline -PipelineArguments $AttemptArguments.ToArray() -LogPath $PipelineLog
        if ($Attempt.ExitCode -notin @(0, 1) -or -not (Test-Path -LiteralPath $ActiveResultPath -PathType Leaf)) {
            Write-LoopSummary -Status 'pipeline_error' -RunDirectory $RunDirectory -Records $Records -Detail "Candidate validation failed operationally in iteration $Iteration. See $PipelineLog"
            exit 4
        }

        $Validation = Get-Content -Raw $ActiveResultPath | ConvertFrom-Json
        Copy-Item -LiteralPath $ActiveResultPath -Destination (Join-Path $IterationDirectory 'validation.json') -Force
        foreach ($Name in @('frida-1.log', 'logcat-1.log')) {
            $Source = Join-Path $RunDirectory ("logs\$Name")
            if (Test-Path -LiteralPath $Source) {
                Copy-Item -LiteralPath $Source -Destination (Join-Path $IterationDirectory $Name) -Force
            }
        }

        $CandidateHash = (Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        $Fingerprint = Get-AttemptFingerprint -CandidateHash $CandidateHash -Validation $Validation
        $Record = [ordered]@{
            iteration = $Iteration
            candidate = Get-RelativeWorkspacePath $Candidate
            candidate_sha256 = $CandidateHash
            codex = $Decision
            pipeline_exit_code = $Attempt.ExitCode
            validation = $Validation
        }
        $Records += $Record
        $Record | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $IterationDirectory 'record.json') -Encoding UTF8

        if ($Validation.success) {
            Write-LoopSummary -Status 'success' -RunDirectory $RunDirectory -Records $Records -Detail "Success policy passed in iteration $Iteration."
            exit 0
        }
        if ($PreviousFingerprint -and $Fingerprint -eq $PreviousFingerprint) {
            Write-LoopSummary -Status 'no_progress' -RunDirectory $RunDirectory -Records $Records -Detail 'Two consecutive attempts produced the same candidate and validation result.'
            exit 5
        }
        if ($Decision.decision -eq 'no_change') {
            Write-LoopSummary -Status 'human_review' -RunDirectory $RunDirectory -Records $Records -Detail 'Codex found no justified change and the success policy still failed.'
            exit 3
        }

        $PreviousFingerprint = $Fingerprint
        $PreviousCandidate = $Candidate
    }

    Write-LoopSummary -Status 'max_iterations' -RunDirectory $RunDirectory -Records $Records -Detail "The success policy did not pass within the $MaxIterations attempts allowed for this invocation."
    exit 6
} finally {
    Pop-Location
}

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Command
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    docker compose up -d --build
    if (-not $Command -or $Command.Count -eq 0) {
        docker compose exec worker bash
    }
    else {
        # Pass arguments individually so paths/spaces do not get re-parsed by a shell.
        $Service = if ($Command[0] -in @('analyzeHeadless', 'ghidraRun')) { 'reverse-engineering' } else { 'worker' }
        docker compose exec -T $Service @Command
    }
}
finally {
    Pop-Location
}

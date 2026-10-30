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
        docker compose exec reverse-engineering bash
    }
    else {
        # Pass arguments individually so paths/spaces do not get re-parsed by a shell.
        docker compose exec -T reverse-engineering @Command
    }
}
finally {
    Pop-Location
}

<#
.SYNOPSIS
Print the latest BELGI run attempt and triage file paths.

.USAGE
pwsh -File scripts/belgi_latest_run.ps1 [-Root <repo_root>]
#>

[CmdletBinding()]
param(
  [string]$Root = "."
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-PythonCommand {
  if (Get-Command python -ErrorAction SilentlyContinue) {
    return @{ Exe = "python"; PrefixArgs = @() }
  }
  if (Get-Command py -ErrorAction SilentlyContinue) {
    return @{ Exe = "py"; PrefixArgs = @("-3") }
  }
  throw "[belgi latest-run] ERROR: python runtime is required but was not found in PATH."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$entrypoint = Join-Path $scriptDir "belgi_latest_run.py"
if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) {
  throw "[belgi latest-run] ERROR: missing helper script: $entrypoint"
}

$repoRoot = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).Path
$pyInfo = Resolve-PythonCommand

& $pyInfo.Exe @($pyInfo.PrefixArgs) $entrypoint --root $repoRoot
$rc = $LASTEXITCODE
exit $rc

param(
  [string]$Repo = ".",
  [string]$Remote = "origin",
  [string]$DefaultBranch = "org",
  [switch]$SyncBranch,
  [switch]$AllowDirty
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-Python {
  # Prefer py -3.13 if available; fall back to python.
  if (Get-Command py -ErrorAction SilentlyContinue) {
    return @{ Exe = "py"; PrefixArgs = @("-3.13") }
  }
  if (Get-Command python -ErrorAction SilentlyContinue) {
    return @{ Exe = "python"; PrefixArgs = @() }
  }
  throw "Neither 'py' nor 'python' found in PATH."
}

function Resolve-RuffPython([string]$repoRoot, [hashtable]$fallbackPyInfo) {
  $venvWindows = Join-Path $repoRoot ".venv/Scripts/python.exe"
  if (Test-Path $venvWindows -PathType Leaf) {
    return @{ Exe = $venvWindows; PrefixArgs = @() }
  }

  $venvPosix = Join-Path $repoRoot ".venv/bin/python"
  if (Test-Path $venvPosix -PathType Leaf) {
    return @{ Exe = $venvPosix; PrefixArgs = @() }
  }

  return $fallbackPyInfo
}

function Run-Git([string]$label, [string[]]$gitArgs, [switch]$AllowFail) {
  Write-Host ""
  Write-Host "==> $label"
  Write-Host ("CMD: git " + ($gitArgs -join " "))
  & git @gitArgs
  $rc = $LASTEXITCODE
  if (-not $AllowFail -and $rc -ne 0) { throw "Git step failed ($label) with exit code $rc" }
  return $rc
}

function Run-Step([string]$label, [hashtable]$pyInfo, [string[]]$cmdArgs) {
  Write-Host ""
  Write-Host "==> $label"
  $exe = $pyInfo.Exe
  $prefix = [string[]]$pyInfo.PrefixArgs
  $cmdLine = ($exe + " " + (($prefix + $cmdArgs) -join " ")).Trim()
  Write-Host ("CMD: " + $cmdLine)

  & $exe @prefix @cmdArgs
  $rc = $LASTEXITCODE
  if ($rc -ne 0) { throw "Step failed ($label) with exit code $rc" }
}

function Assert-NotCI {
  if ($env:GITHUB_ACTIONS -eq "true" -or $env:CI -eq "true") {
    throw "Refusing to run dev-sync in CI. This is a LOCAL fixer only."
  }
}

function Get-RepoRoot([string]$repoArg) {
  $resolved = Resolve-Path $repoArg
  Push-Location $resolved.Path
  try {
    $top = (& git rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $top) { throw "Not a git repo: $($resolved.Path)" }
    return (Resolve-Path $top).Path
  } finally {
    Pop-Location
  }
}

function Assert-CleanTree([switch]$allowDirty) {
  $status = (& git status --porcelain)
  if ($LASTEXITCODE -ne 0) { throw "git status failed" }
  if (-not $allowDirty -and $status) {
    Write-Host ""
    Write-Host "NO-GO: working tree is dirty. Commit/stash first, or rerun with -AllowDirty."
    Write-Host "Dirty files:"
    $status | ForEach-Object { Write-Host ("  " + $_) }
    throw "Dirty working tree"
  }
}

function Assert-NoMergeConflicts {
  $u = (& git diff --name-only --diff-filter=U)
  if ($LASTEXITCODE -ne 0) { throw "git diff failed while checking conflicts" }
  if ($u) {
    Write-Host ""
    Write-Host "NO-GO: merge conflicts still present (resolve these, then rerun dev-sync):"
    $u | ForEach-Object { Write-Host ("  " + $_) }
    throw "Merge conflicts present"
  }
}

Assert-NotCI

$pyInfo = Resolve-Python
$repoRoot = Get-RepoRoot $Repo
$ruffPyInfo = Resolve-RuffPython $repoRoot $pyInfo

Push-Location $repoRoot
try {
  # Optional: keep your CURRENT branch updated with origin/org before running fixers.
  # This reduces “surprise conflicts” later.
  if ($SyncBranch) {
    Run-Git "Fetch remote ($Remote)" @("fetch", $Remote) | Out-Null
    Assert-CleanTree -allowDirty:$AllowDirty

    $currentBranch = (& git rev-parse --abbrev-ref HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $currentBranch) { throw "Failed to detect current branch" }

    Write-Host ""
    Write-Host "==> Sync current branch with $Remote/$DefaultBranch"
    Write-Host ("Current branch: " + $currentBranch)
    Write-Host ("Merging: " + $Remote + "/" + $DefaultBranch + " -> " + $currentBranch)
    $rc = Run-Git "Merge $Remote/$DefaultBranch into $currentBranch" @("merge", "--no-edit", "$Remote/$DefaultBranch") -AllowFail
    if ($rc -ne 0) {
      Assert-NoMergeConflicts
      throw "Merge failed for an unknown reason (rc=$rc)."
    }
  }

  Assert-CleanTree -allowDirty:$AllowDirty
  Assert-NoMergeConflicts

  # --- Local deterministic fixer pipeline ---
  Run-Step "Byte Guard (normalize check)" $pyInfo @("-m","tools.normalize","--repo",".","--check","--tracked-only")
  Run-Step "Protocol Pack Drift Guard"    $pyInfo @("-m","tools.check_drift")
  Run-Step "Ruff lint"                    $ruffPyInfo @("-m","ruff","check","belgi","chain","tools","wrapper","tests","scripts",".github/scripts")

  # Local calibration: keep builtin protocol pack manifest in sync.
  Run-Step "Protocol Pack Manifest (rehash)"              $pyInfo @("-m","tools.rehash","protocol-pack","--pack","belgi/_protocol_packs/v1")

  Run-Step "Consistency sweep (VERIFY)"                   $pyInfo @("-m","tools.sweep","consistency","--repo",".")

  Write-Host ""
  Write-Host "OK: dev-sync completed."

  $porcelain = (& git status --porcelain)
  if ($LASTEXITCODE -ne 0) { throw "git status failed" }

  if (-not $porcelain) {
    Write-Host "Working tree is clean (no changes)."
  } else {
    Write-Host "Now commit the changes produced by dev-sync:"
    $porcelain | ForEach-Object { Write-Host ("  " + $_) }
  }

} finally {
  Pop-Location
}

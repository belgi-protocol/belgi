<#
.SYNOPSIS
Create a temporary tracked-only WIP commit, run BELGI, then restore original HEAD.

.USAGE
pwsh -File scripts/belgi_wip_commit_run_reset.ps1 [--] [belgi command ...]
pwsh -File scripts/belgi_wip_commit_run_reset.ps1 -- python -m belgi.cli run --repo . --tier tier-1

.NOTES
- Fails closed if merge/rebase is in progress.
- Fails closed if staged changes exist before running.
- Stages tracked files only via `git add -u`.
- Always attempts restore in a finally block.
#>

[CmdletBinding()]
param(
  [string]$Repo = ".",
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$BelgiCommand
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-RepoRoot([string]$repoArg) {
  $resolved = Resolve-Path -LiteralPath $repoArg -ErrorAction Stop
  Push-Location $resolved.Path
  try {
    $top = (& git rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $top) {
      throw "NO-GO: target is not a git repository: $($resolved.Path)"
    }
    return (Resolve-Path -LiteralPath $top.Trim() -ErrorAction Stop).Path
  } finally {
    Pop-Location
  }
}

function Assert-NoMergeOrRebaseInProgress {
  $gitDirRaw = (& git rev-parse --git-dir 2>$null)
  if ($LASTEXITCODE -ne 0 -or -not $gitDirRaw) {
    throw "NO-GO: unable to resolve .git directory."
  }
  $gitDirRaw = $gitDirRaw.Trim()
  $gitDir = if ([System.IO.Path]::IsPathRooted($gitDirRaw)) {
    $gitDirRaw
  } else {
    Join-Path (Get-Location).Path $gitDirRaw
  }

  & git rev-parse --verify -q MERGE_HEAD *> $null
  if ($LASTEXITCODE -eq 0) {
    throw "NO-GO: merge in progress (MERGE_HEAD exists). Resolve/abort merge, then rerun."
  }

  if ((Test-Path -LiteralPath (Join-Path $gitDir "rebase-merge")) -or (Test-Path -LiteralPath (Join-Path $gitDir "rebase-apply"))) {
    throw "NO-GO: rebase in progress (rebase-merge/rebase-apply detected). Resolve/abort rebase, then rerun."
  }
}

function Assert-NoStagedChanges {
  & git diff --cached --quiet --exit-code
  $rc = $LASTEXITCODE
  if ($rc -eq 0) {
    return
  }
  if ($rc -eq 1) {
    throw "NO-GO: staged changes detected. Unstage everything first (`git reset`), then rerun."
  }
  throw "NO-GO: staged-changes preflight failed (git diff --cached rc=$rc)."
}

function Get-DefaultBelgiCommand {
  if (Get-Command python -ErrorAction SilentlyContinue) {
    return @("python", "-m", "belgi.cli", "run", "--repo", ".", "--tier", "tier-0")
  }
  if (Get-Command py -ErrorAction SilentlyContinue) {
    return @("py", "-3", "-m", "belgi.cli", "run", "--repo", ".", "--tier", "tier-0")
  }
  throw "NO-GO: no command was provided and no Python runtime was found for default BELGI run."
}

function Invoke-NativeCommand([string[]]$Command) {
  if (-not $Command -or $Command.Count -lt 1) {
    throw "NO-GO: empty command invocation."
  }
  if ($Command.Count -eq 1) {
    & $Command[0]
  } else {
    & $Command[0] @($Command[1..($Command.Count - 1)])
  }
  return $LASTEXITCODE
}

function Get-LatestBelgiRunAttempt([string]$RepoRoot) {
  $roots = @()
  $roots += Join-Path $RepoRoot ".belgi/runs"
  $dotBelgiDirs = @(Get-ChildItem -LiteralPath $RepoRoot -Force -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ".belgi*" })
  foreach ($d in $dotBelgiDirs) {
    $candidate = Join-Path $d.FullName "runs"
    if ($roots -notcontains $candidate) {
      $roots += $candidate
    }
  }

  $latestPath = $null
  $latestTicks = [Int64]::MinValue
  foreach ($runsRoot in $roots) {
    if (-not (Test-Path -LiteralPath $runsRoot -PathType Container)) {
      continue
    }
    $summaries = Get-ChildItem -LiteralPath $runsRoot -File -Filter "run.summary.json" -Recurse -ErrorAction SilentlyContinue
    foreach ($summary in $summaries) {
      $ticks = $summary.LastWriteTimeUtc.Ticks
      if ($ticks -gt $latestTicks) {
        $latestTicks = $ticks
        $latestPath = $summary.Directory.FullName
      }
    }
  }
  return $latestPath
}

$repoRoot = Resolve-RepoRoot -repoArg $Repo
$originalHead = ""
$tempCommitSha = ""
$runRc = 0
$runPath = ""
$restorePatchPath = ""
$restorePatchText = ""
$restoreFailed = $false
$scriptFailure = $null

Push-Location $repoRoot
try {
  $originalHead = (& git rev-parse --verify HEAD 2>$null).Trim()
  if ($LASTEXITCODE -ne 0 -or -not $originalHead) {
    throw "NO-GO: failed to resolve current HEAD."
  }
  Write-Host "[belgi wip] original_head: $originalHead"

  Assert-NoMergeOrRebaseInProgress
  Assert-NoStagedChanges

  $diffLines = @(& git diff --binary --no-color)
  if ($LASTEXITCODE -ne 0) {
    throw "NO-GO: failed to capture tracked working-tree diff before WIP commit."
  }
  if ($diffLines.Count -gt 0) {
    $restorePatchText = ($diffLines -join "`n")
    if (-not $restorePatchText.EndsWith("`n")) {
      $restorePatchText += "`n"
    }
  }

  try {
    & git add -u
    if ($LASTEXITCODE -ne 0) {
      throw "NO-GO: git add -u failed."
    }

    & git diff --cached --quiet --exit-code
    $stagedAfterAddRc = $LASTEXITCODE
    if ($stagedAfterAddRc -eq 0) {
      throw "NO-GO: no tracked changes to commit. Edit tracked files, then rerun."
    }
    if ($stagedAfterAddRc -ne 1) {
      throw "NO-GO: unable to evaluate staged state after git add -u (rc=$stagedAfterAddRc)."
    }

    $wipMessage = "chore(wrapper): temporary wip commit for belgi run (auto-reset)"
    & git commit -m $wipMessage
    if ($LASTEXITCODE -ne 0) {
      throw "NO-GO: failed to create temporary WIP commit."
    }

    $tempCommitSha = (& git rev-parse --verify HEAD 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $tempCommitSha) {
      throw "NO-GO: failed to resolve temporary commit sha."
    }
    Write-Host "[belgi wip] temp_commit: $tempCommitSha"

    $beforeRunPath = Get-LatestBelgiRunAttempt -RepoRoot $repoRoot
    $runCommand = if ($BelgiCommand -and $BelgiCommand.Count -gt 0) { @($BelgiCommand) } else { Get-DefaultBelgiCommand }
    Write-Host ("[belgi wip] run command: " + ($runCommand -join " "))

    $runRc = Invoke-NativeCommand -Command $runCommand
    $afterRunPath = Get-LatestBelgiRunAttempt -RepoRoot $repoRoot
    if ($afterRunPath) {
      $runPath = $afterRunPath
    } elseif ($beforeRunPath) {
      $runPath = $beforeRunPath
    }
  } finally {
    $restoreErrors = New-Object System.Collections.Generic.List[string]

    if ($tempCommitSha) {
      & git reset --hard $originalHead *> $null
      if ($LASTEXITCODE -ne 0) {
        $restoreErrors.Add("git reset --hard $originalHead failed (rc=$LASTEXITCODE).")
      }

      if ($restoreErrors.Count -eq 0 -and $restorePatchText.Length -gt 0) {
        $restorePatchPath = Join-Path ([System.IO.Path]::GetTempPath()) ("belgi_wip_restore_" + [Guid]::NewGuid().ToString("N") + ".patch")
        try {
          Set-Content -LiteralPath $restorePatchPath -Value $restorePatchText -Encoding utf8NoBOM -NoNewline
        } catch {
          $restoreErrors.Add("failed to write temporary restore patch: $($_.Exception.Message)")
        }

        if ($restoreErrors.Count -eq 0) {
          & git apply --whitespace=nowarn -- $restorePatchPath
          if ($LASTEXITCODE -ne 0) {
            $restoreErrors.Add("git apply restore patch failed (rc=$LASTEXITCODE).")
          }
        }
      }
    } else {
      & git reset --mixed HEAD *> $null
      if ($LASTEXITCODE -ne 0) {
        $restoreErrors.Add("git reset --mixed HEAD failed (rc=$LASTEXITCODE).")
      }
    }

    $headAfterRestore = (& git rev-parse --verify HEAD 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $headAfterRestore) {
      $restoreErrors.Add("git rev-parse --verify HEAD failed after restore.")
    } elseif ($headAfterRestore -ne $originalHead) {
      $restoreErrors.Add("HEAD mismatch after restore: expected $originalHead, got $headAfterRestore.")
    }

    if ($restorePatchPath -and (Test-Path -LiteralPath $restorePatchPath)) {
      Remove-Item -LiteralPath $restorePatchPath -Force -ErrorAction SilentlyContinue
    }

    if ($restoreErrors.Count -gt 0) {
      $restoreFailed = $true
      Write-Error "[belgi wip] NO-GO: failed to restore repository state."
      foreach ($line in $restoreErrors) {
        Write-Error ("[belgi wip] " + $line)
      }
      Write-Host "[belgi wip] Recovery steps:"
      Write-Host "  1. git reset --hard $originalHead"
      if ($restorePatchText.Length -gt 0) {
        Write-Host "  2. Reapply your original tracked diff from backup if needed."
      } else {
        Write-Host "  2. Confirm your worktree is clean (`git status --short`)."
      }
      Write-Host "  3. Re-run this helper only after state is stable."
    }
  }
} catch {
  $scriptFailure = $_
} finally {
  Pop-Location
}

if ($restoreFailed) {
  exit 2
}

if ($scriptFailure -ne $null) {
  Write-Error ("[belgi wip] NO-GO: " + $scriptFailure.Exception.Message)
  exit 2
}

Write-Host "[belgi wip] resulting_run_path: $runPath"
if ($runRc -ne 0) {
  Write-Error "[belgi wip] BELGI command failed with exit code $runRc."
  exit $runRc
}
exit 0

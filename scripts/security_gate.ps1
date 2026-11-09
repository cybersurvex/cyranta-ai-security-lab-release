$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

function Assert-LastExitCode {
    param(
        [string]$StepName
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$StepName failed with exit code $LASTEXITCODE"
    }
}

Write-Host ""
Write-Host "=== Cyranta AI Security Gate ==="
Write-Host ""

Write-Host "[1/5] Python syntax validation"
python -m compileall -q app tests redteam/pyrit
Assert-LastExitCode "Python syntax validation"

Write-Host "[2/5] Ruff static analysis"
ruff check app tests
Assert-LastExitCode "Ruff"

Write-Host "[3/5] Security regression suite"
python -m pytest -q
Assert-LastExitCode "Pytest"

Write-Host "[4/5] Bandit application security scan"
bandit -q -r app
Assert-LastExitCode "Bandit"

Write-Host "[5/5] Python dependency vulnerability audit"
pip-audit -r requirements.txt
Assert-LastExitCode "pip-audit"

Write-Host ""
Write-Host "CYRANTA SECURITY GATE: PASSED"
Write-Host ""
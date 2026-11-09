$ErrorActionPreference = 'Stop'

Write-Host "[1/4] Checking Python..."
$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) {
  throw "Python launcher 'py' not found. Install Python 3.11 x64, then reopen PowerShell."
}

Write-Host "[2/4] Creating Python 3.11 virtual environment..."
py -3.11 -m venv .venv

Write-Host "[3/4] Activating virtual environment..."
& .\.venv\Scripts\Activate.ps1

Write-Host "[4/4] Installing application and security-test dependencies..."
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

if (-not (Test-Path .env)) {
  Copy-Item .env.example .env
  Write-Host "Created .env from .env.example"
}

Write-Host "Bootstrap complete. Next: .\\scripts\\run_app.ps1"

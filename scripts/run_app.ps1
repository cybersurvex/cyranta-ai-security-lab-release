$ErrorActionPreference = 'Stop'
if (-not (Test-Path .\.venv\Scripts\python.exe)) {
  throw "Virtual environment not found. Run .\\scripts\\bootstrap.ps1 first."
}
& .\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

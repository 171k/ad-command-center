# Run backend + frontend for local development (Windows PowerShell).
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent

Push-Location "$root\backend"
if (-not (Test-Path .venv)) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install -q -r requirements-dev.txt
Start-Process -NoNewWindow -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "-m","uvicorn","app.main:app","--reload","--port","8000"
Pop-Location

Push-Location "$root\frontend"
if (-not (Test-Path node_modules)) { npm install }
Write-Host "Backend :8000  Frontend :5173  (close this window to stop the frontend)"
npm run dev
Pop-Location

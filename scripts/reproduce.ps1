# One-command experiment reproduction wrapper for Windows PowerShell
$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Running ACIP One-Command Reproducibility Suite (PowerShell) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$PythonExe = ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

& $PythonExe scripts\reproduce_results.py experiments\results
if ($LASTEXITCODE -ne 0) {
    Write-Host "Reproduction suite failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Reproduction suite succeeded." -ForegroundColor Green

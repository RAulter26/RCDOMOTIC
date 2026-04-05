$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Write-Host "Repo:" (Get-Location).Path
Write-Host "Este script saca datos sensibles de Git sin borrarlos del disco." -ForegroundColor Yellow

git rm --cached --ignore-unmatch rc_domotic.db
git rm -r --cached --ignore-unmatch uploads

Write-Host ""
Write-Host "Estado resultante:" -ForegroundColor Cyan
git status --short

Write-Host ""
Write-Host "Siguiente paso sugerido:" -ForegroundColor Cyan
Write-Host "  git add .gitignore .env.example SECURITY_REMEDIATION_STATUS.md scripts/remove_sensitive_from_git.ps1"
Write-Host "  git commit -m \"Harden auth and stop tracking local business data\""

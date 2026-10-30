@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0codex-loop.ps1" %*
exit /b %errorlevel%

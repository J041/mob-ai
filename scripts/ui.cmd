@echo off
setlocal
pushd "%~dp0.."
docker compose up -d --build --wait %*
set "exit_code=%errorlevel%"
if "%exit_code%"=="0" echo Mob-AI Control Room: http://127.0.0.1:8787/
popd
exit /b %exit_code%

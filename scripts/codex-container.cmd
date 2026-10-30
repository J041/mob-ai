@echo off
setlocal
pushd "%~dp0.."

docker compose up -d --build
if errorlevel 1 goto :failed

if "%~1"=="" (
  docker compose exec reverse-engineering bash
) else (
  docker compose exec -T reverse-engineering %*
)
set "exit_code=%errorlevel%"
popd
exit /b %exit_code%

:failed
set "exit_code=%errorlevel%"
popd
exit /b %exit_code%

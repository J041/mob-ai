@echo off
setlocal
pushd "%~dp0.."

docker compose up -d --build
if errorlevel 1 goto :failed

if /I "%~1"=="analyzeHeadless" (
  docker compose exec reverse-engineering %*
) else if /I "%~1"=="ghidraRun" (
  docker compose exec reverse-engineering %*
) else (
  docker compose exec worker %*
)
set "exit_code=%errorlevel%"
popd
exit /b %exit_code%

:failed
set "exit_code=%errorlevel%"
popd
exit /b %exit_code%

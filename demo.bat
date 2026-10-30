@echo off
REM AgentShield - Windows launcher. Uses the py launcher, falls back to python.
cd /d "%~dp0"
set PYTHONUTF8=1
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 -m agentshield.demo %*
) else (
  python -m agentshield.demo %*
)
pause

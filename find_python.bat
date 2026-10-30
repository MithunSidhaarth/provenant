@echo off
REM Provenant - find a working Python 3.10+ and put its command in PY.
REM Each candidate is checked with --version, so the Microsoft Store alias stub
REM (which exists on PATH but does not run Python) is skipped.
set "PY="
for %%P in ("py -3" python python3 python3.13 python3.12 python3.11 python3.10) do (
  %%~P -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && (
    set "PY=%%~P"
    goto :found
  )
)
echo Could not find Python 3.10 or newer. Install it from https://www.python.org/downloads/ and try again.
exit /b 1
:found
%PY% --version
exit /b 0

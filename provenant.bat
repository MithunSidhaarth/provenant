@echo off
REM Provenant - Windows launcher for the real-tool guard: provenant.bat setup | status | log -f | approve ID ...
set PYTHONUTF8=1
call "%~dp0find_python.bat" || exit /b 1
%PY% "%~dp0provenant.py" %*

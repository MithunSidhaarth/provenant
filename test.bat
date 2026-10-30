@echo off
REM Provenant - Windows launcher.
cd /d "%~dp0"
set PYTHONUTF8=1
call "%~dp0find_python.bat" || (pause & exit /b 1)
%PY% -m unittest discover -s tests -t . %*
pause

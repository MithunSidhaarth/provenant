@echo off
REM Provenant - find a working Python 3.10+ and put its command in PY.
REM Every candidate must actually run and report 3.10 or newer, so the Microsoft Store alias
REM stub is skipped. Full paths are tried too, for machines where WindowsApps is not on PATH.
set "PY="
for %%P in ("py -3" python python3 python3.13 python3.12 python3.11 python3.10) do if not defined PY call :try %%~P
for %%V in (13 12 11 10) do if not defined PY call :try "%LOCALAPPDATA%\Microsoft\WindowsApps\python3.%%V.exe"
if not defined PY call :try "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe"
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do if not defined PY call :try "%%~D\python.exe"
for /d %%D in ("%ProgramFiles%\Python3*") do if not defined PY call :try "%%~D\python.exe"
if defined PY goto :found
echo Could not find Python 3.10 or newer. Install it from https://www.python.org/downloads/ and try again.
exit /b 1
:found
echo Using %PY%
%PY% --version
exit /b 0

:try
%* -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PY=%*"
exit /b 0

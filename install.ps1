# Provenant installer for Windows (PowerShell 5.1+). Run as yourself, not as an agent:
#   irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex
# Installs the `provenant` Python package for the current user (no admin, no dependencies),
# adds a `provenant` command to your user PATH, then runs `provenant setup`, which shows what it will
# protect and asks before changing anything.
$ErrorActionPreference = 'Stop'
$Version = '0.9.0'   # kept equal to pyproject.toml by tests/test_packaging.py
$Src = if ($env:PROVENANT_SRC) { $env:PROVENANT_SRC } else { "https://github.com/MithunSidhaarth/provenant/raw/main/dist/provenant-$Version-py3-none-any.whl" }
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$Ok = [char]0x2713; $No = [char]0x2717; $Dia = [char]0x25C6; $Dot = [char]0x00B7
function Step($n, $msg)   { Write-Host "  [$n/4] " -ForegroundColor DarkGray -NoNewline; Write-Host $msg -NoNewline }
function Done($detail)    { Write-Host "  $Ok " -ForegroundColor Green -NoNewline; Write-Host $detail -ForegroundColor DarkGray }
function Fail($msg)       { Write-Host ""; Write-Host "  $No $msg" -ForegroundColor Red; Write-Host "" }

function Find-Python {
    $probe = 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
    $cands = @(@('py', '-3'), @('python'), @('python3'))
    foreach ($v in 13, 12, 11, 10) { $cands += ,@("$env:LOCALAPPDATA\Microsoft\WindowsApps\python3.$v.exe") }
    Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe", "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue |
        ForEach-Object { $cands += ,@($_.FullName) }
    foreach ($c in $cands) {
        try {
            $exe = $c[0]; $pre = @($c | Select-Object -Skip 1)
            & $exe @pre -c $probe 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { return (& $exe @pre -c 'import sys; print(sys.executable)').Trim() }
        } catch { }
    }
    return $null
}

Write-Host ""
Write-Host "  $Dia " -ForegroundColor Magenta -NoNewline
Write-Host "provenant" -NoNewline
Write-Host "  $Dot a firewall between AI agents and their tools" -ForegroundColor DarkGray
Write-Host ""

Step 1 "Finding Python 3.10+     "
$py = Find-Python
if (-not $py) { Fail "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ and run this again."; return }
$pyver = (& $py -c 'import sys; print(".".join(map(str, sys.version_info[:3])))').Trim()
Done "Python $pyver"

Step 2 "Installing Provenant     "
$log = Join-Path $env:TEMP 'provenant-install.log'
& $py -m pip install --user --upgrade --disable-pip-version-check --no-warn-script-location $Src *> $log
if ($LASTEXITCODE -ne 0) { Fail "pip could not install Provenant. Details: $log"; return }
$ver = (& $py -m agentshield.cli --version 2>$null) -replace '^provenant\s*', ''
Done "provenant $ver for $env:USERNAME (no admin needed)"

Step 3 "Adding the command       "
$bin = Join-Path $HOME '.provenant\bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null
Set-Content -Path (Join-Path $bin 'provenant.cmd') -Encoding ASCII -Value "@echo off`r`nset PYTHONUTF8=1`r`n`"$py`" -m agentshield.cli %*"
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $bin)) {
    [Environment]::SetEnvironmentVariable('Path', ($(if ($userPath) { "$userPath;" } else { '' }) + $bin), 'User')
}
if (-not (($env:Path -split ';') -contains $bin)) { $env:Path = "$env:Path;$bin" }
Done "'provenant' works in any new terminal"

Step 4 "Protecting your agents   "
Write-Host ""
& (Join-Path $bin 'provenant.cmd') setup
Write-Host ""
Write-Host "  Next: provenant verify   (safe enforcement test), then provenant status"
Write-Host "  Open a NEW terminal first if 'provenant' is not recognized here, or run: py -m provenant verify" -ForegroundColor DarkGray

# Provenant installer for Windows (PowerShell 5.1+). Run as yourself, not as an agent:
#   irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex
# Installs the `provenant` Python package for the current user (no admin, no dependencies),
# adds a `provenant` command to your user PATH, then runs `provenant setup`, which shows what it will
# protect and asks before changing anything.
$ErrorActionPreference = 'Stop'
$Src = if ($env:PROVENANT_SRC) { $env:PROVENANT_SRC } else { 'https://github.com/MithunSidhaarth/provenant/archive/refs/heads/main.zip' }

function Write-Step($msg) { Write-Host "  > $msg" -ForegroundColor Cyan }

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
Write-Host "  provenant installer" -ForegroundColor Magenta
$py = Find-Python
if (-not $py) {
    Write-Host "  Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ and run this again." -ForegroundColor Red
    return
}
Write-Step "Using $py"

Write-Step "Installing Provenant for $env:USERNAME"
& $py -m pip install --user --upgrade --disable-pip-version-check --quiet $Src
if ($LASTEXITCODE -ne 0) { Write-Host "  pip install failed." -ForegroundColor Red; return }

# A tiny launcher on the user PATH, so `provenant` works in any new terminal.
$bin = Join-Path $HOME '.provenant\bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null
Set-Content -Path (Join-Path $bin 'provenant.cmd') -Encoding ASCII -Value "@echo off`r`nset PYTHONUTF8=1`r`n`"$py`" -m agentshield.cli %*"
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $bin)) {
    [Environment]::SetEnvironmentVariable('Path', ($(if ($userPath) { "$userPath;" } else { '' }) + $bin), 'User')
    Write-Step "Added $bin to your user PATH"
}
if (-not (($env:Path -split ';') -contains $bin)) { $env:Path = "$env:Path;$bin" }

Write-Step "Done. Running provenant setup"
& (Join-Path $bin 'provenant.cmd') setup

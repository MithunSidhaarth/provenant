# Provenant installer for Windows (Windows PowerShell 5.1 and PowerShell 7+). Run as yourself, not as an agent:
#   irm https://raw.githubusercontent.com/MithunSidhaarth/provenant/main/install.ps1 | iex
# Finds Python 3.10+, downloads the published wheel, checks it is a real wheel of the right version (and, for the
# official download, that its SHA-256 matches the value pinned below), installs it for the current user (no admin,
# no dependencies), adds a `provenant` command to your user PATH, then runs `provenant setup`, which shows a plan and
# asks before changing anything.
#
# Rules this file follows (tests/test_installer.py enforces them):
#  * Python code passed to `python -c` never contains a double quote. Windows PowerShell 5.1 strips double quotes
#    from native-command arguments, which turned print(".".join(...)) into print(..join(...)) in 0.9.0.
#  * Every native command's exit code is read right after it runs and a failed command's output is never used.
#  * The file is plain ASCII and never calls `exit` when piped into iex (that would close the user's window).

$PvVersion = '0.10.1'                # kept equal to pyproject.toml by tests/test_installer.py
$PvWheelSha256 = '46b272cd524fc3a5dd16f399bdd5702a221869b2c887f3761c2e77071a44b56a'   # rewritten by scripts/build_release.py
$PvMinCode = 31000                  # Python 3.10.0 as major*10000 + minor*100 + micro
$PvProbeCode = 'import sys; print(sys.executable); print(sys.version_info[0] * 10000 + sys.version_info[1] * 100 + sys.version_info[2]); print(int(sys.prefix != sys.base_prefix))'
$PvImportCode = 'import agentshield.cli as c; print(c.VERSION)'
$PvWheelCheckCode = @'
import sys, zipfile
path, version = sys.argv[1], sys.argv[2]
with open(path, 'rb') as fh:
    head = fh.read(4)
if head != b'PK\x03\x04':
    print('not a wheel (the file starts with %r). A web page or error page was probably saved instead.' % head[:20])
    sys.exit(2)
try:
    z = zipfile.ZipFile(path)
    bad = z.testzip()
    names = z.namelist()
except Exception as exc:
    print('the wheel is corrupt or truncated: %s' % exc)
    sys.exit(2)
if bad:
    print('the wheel is corrupt: bad member %s' % bad)
    sys.exit(2)
meta = [n for n in names if n.endswith('.dist-info/METADATA')]
if not meta:
    print('the wheel has no package metadata')
    sys.exit(2)
found = None
for line in z.read(meta[0]).decode('utf-8', 'replace').splitlines():
    if line.startswith('Version:'):
        found = line.split(':', 1)[1].strip()
        break
if found != version:
    print('the wheel is version %s but this installer installs %s' % (found, version))
    sys.exit(2)
missing = [n for n in ('agentshield/cli.py', 'agentshield/guard_policy.json') if n not in names]
eps = [n for n in names if n.endswith('entry_points.txt')]
if missing or not eps or b'agentshield.cli:main' not in z.read(eps[0]):
    print('the wheel is missing required files: %s' % (missing or 'console entry point'))
    sys.exit(2)
print('ok')
'@

# ---- output helpers --------------------------------------------------------------------------------------------
$PvOk = [char]0x2713; $PvNo = [char]0x2717; $PvDia = [char]0x25C6; $PvDot = [char]0x00B7
function Pv-Step($n, $msg) { Write-Host "  [$n/5] " -ForegroundColor DarkGray -NoNewline; Write-Host ($msg.PadRight(26)) -NoNewline }
function Pv-Done($detail) { Write-Host "  $PvOk " -ForegroundColor Green -NoNewline; Write-Host $detail -ForegroundColor DarkGray }
function Pv-Fail($what, $fix) {
    Write-Host ""
    Write-Host "  $PvNo $what" -ForegroundColor Red
    if ($fix) { Write-Host "    $fix" -ForegroundColor Yellow }
    Write-Host ""
}

# ---- run a program without ever throwing; returns Code (int) and Out (string[]) --------------------------------
function Pv-Native {
    param([string]$Exe, [string[]]$Arguments = @(), [string]$Cwd = '')
    $result = [pscustomobject]@{ Code = -1; Out = @() }
    $prev = $ErrorActionPreference
    $moved = $false
    try {
        $ErrorActionPreference = 'Continue'
        if ($Cwd) { Push-Location -LiteralPath $Cwd; $moved = $true }
        $lines = & $Exe @Arguments 2>&1
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = -1 }
        $result.Code = [int]$code
        $result.Out = @($lines | ForEach-Object { "$_" })
    } catch {
        $result.Code = -1
        $result.Out = @($_.Exception.Message)
    } finally {
        if ($moved) { Pop-Location }
        $ErrorActionPreference = $prev
    }
    return $result
}

function Pv-RunTimed {
    # Runs a program with no console input, a time limit, and its output captured as one string. Never throws.
    param([string]$Exe, [string]$ArgString, [int]$Seconds)
    $r = [pscustomobject]@{ Code = -1; Out = ''; TimedOut = $false }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.Arguments = $ArgString
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
        $psi.EnvironmentVariables['PYTHONUTF8'] = '1'
        $psi.EnvironmentVariables['NO_COLOR'] = '1'
        $p = [System.Diagnostics.Process]::Start($psi)
        $p.StandardInput.Close()
        $o = $p.StandardOutput.ReadToEndAsync()
        $e = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($Seconds * 1000)) {
            $r.TimedOut = $true
            try { $p.Kill() } catch { }
            return $r
        }
        $p.WaitForExit()
        $r.Code = $p.ExitCode
        $r.Out = [string]$o.Result + [string]$e.Result
    } catch {
        $r.Out = $_.Exception.Message
    }
    return $r
}

# ---- Python discovery --------------------------------------------------------------------------------------------
function Pv-ProbePython {
    # Returns $null unless Exe runs, exits 0 and prints exactly: an existing interpreter path, a number, 0 or 1.
    param([string]$Exe, [string[]]$Pre = @())
    $r = Pv-Native $Exe (@($Pre) + @('-c', $PvProbeCode))
    if ($r.Code -ne 0) { return $null }
    $lines = @($r.Out | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($lines.Count -ne 3) { return $null }
    $code = 0
    if (-not [int]::TryParse($lines[1], [ref]$code)) { return $null }
    $venv = 0
    if (-not [int]::TryParse($lines[2], [ref]$venv)) { return $null }
    if (-not (Test-Path -LiteralPath $lines[0] -PathType Leaf)) { return $null }
    $major = [int][math]::Floor($code / 10000)
    $minor = [int][math]::Floor(($code % 10000) / 100)
    $micro = [int]($code % 100)
    return [pscustomobject]@{ Path = $lines[0]; Code = $code; Version = "$major.$minor.$micro"; InVenv = ($venv -eq 1) }
}

function Pv-PythonCandidates {
    $list = @()
    $list += , @('py', @('-3'))
    $list += , @('python', @())
    $list += , @('python3', @())
    $roots = @()
    if ($env:LOCALAPPDATA) { $roots += (Join-Path $env:LOCALAPPDATA 'Programs\Python') }
    if ($env:ProgramFiles) { $roots += $env:ProgramFiles }
    foreach ($root in $roots) {
        $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Filter 'Python3*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
        foreach ($d in $dirs) {
            $exe = Join-Path $d.FullName 'python.exe'
            if (Test-Path -LiteralPath $exe -PathType Leaf) { $list += , @($exe, @()) }
        }
    }
    if ($env:LOCALAPPDATA) {
        foreach ($minor in 13, 12, 11, 10) {
            $exe = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\python3.$minor.exe"
            if (Test-Path -LiteralPath $exe -PathType Leaf) { $list += , @($exe, @()) }
        }
    }
    return , $list
}

function Pv-FindPython {
    # Returns @{ Python = <probe result or $null>; Rejected = <strings> }. Never falls back to an unsupported version.
    param($Candidates = $null)
    if ($null -eq $Candidates) { $Candidates = Pv-PythonCandidates }
    $rejected = @()
    foreach ($c in $Candidates) {
        $p = Pv-ProbePython $c[0] $c[1]
        if ($null -eq $p) { continue }
        if ($p.Code -ge $PvMinCode) { return @{ Python = $p; Rejected = $rejected } }
        $rejected += "Python $($p.Version) at $($p.Path) is older than 3.10"
    }
    return @{ Python = $null; Rejected = $rejected }
}

# ---- download and validation -------------------------------------------------------------------------------------
function Pv-Download {
    # Returns $null on success, otherwise the error text.
    param([string]$Url, [string]$Dest)
    $prevProgress = $ProgressPreference
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -MaximumRedirection 5 -ErrorAction Stop | Out-Null
        return $null
    } catch {
        return $_.Exception.Message
    } finally {
        $ProgressPreference = $prevProgress
    }
}

function Pv-CheckWheel {
    # Returns $null when the file is a real wheel of $PvVersion, otherwise the reason it is not.
    param([string]$PythonPath, [string]$Wheel, [string]$Workdir)
    $script = Join-Path $Workdir 'check_wheel.py'
    [IO.File]::WriteAllText($script, $PvWheelCheckCode, (New-Object Text.UTF8Encoding($false)))
    $r = Pv-Native $PythonPath @($script, $Wheel, $PvVersion)
    $text = (($r.Out | ForEach-Object { $_.Trim() }) -join ' ').Trim()
    if ($r.Code -eq 0 -and $text -eq 'ok') { return $null }
    if ($text) { return $text }
    return "the wheel check failed with exit code $($r.Code)"
}

# ---- command wrapper and PATH ------------------------------------------------------------------------------------
function Pv-WriteWrapper {
    # Returns $null on success, otherwise the error text. The path is quoted and % is doubled for cmd.exe.
    param([string]$BinDir, [string]$PythonPath)
    try {
        New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
        $esc = $PythonPath.Replace('%', '%%')
        $text = (@('@echo off', 'set PYTHONUTF8=1', ('"{0}" -m agentshield.cli %*' -f $esc), 'exit /b %ERRORLEVEL%') -join "`r`n") + "`r`n"
        $enc = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
        if ($enc.GetString($enc.GetBytes($text)) -ne $text) {
            return "the Python path contains characters cmd.exe cannot read from a script; run Provenant as: `"$PythonPath`" -m agentshield.cli"
        }
        [IO.File]::WriteAllText((Join-Path $BinDir 'provenant.cmd'), $text, $enc)
        return $null
    } catch {
        return $_.Exception.Message
    }
}

function Pv-AddToPath {
    # Pure function. Returns Current unchanged when Entry is already listed (ignoring case and a trailing slash).
    param([string]$Current, [string]$Entry)
    $parts = @()
    if ($Current) { $parts = @($Current -split ';' | Where-Object { $_.Trim() -ne '' }) }
    $want = $Entry.Trim().TrimEnd('\').ToLowerInvariant()
    foreach ($p in $parts) {
        if ($p.Trim().TrimEnd('\').ToLowerInvariant() -eq $want) { return $Current }
    }
    return (($parts + $Entry) -join ';')
}

function Pv-SetUserPath {
    # Adds BinDir to the user PATH only. Returns 'added', 'present', or 'failed: <reason>'; never throws.
    # %VAR% entries already in PATH are kept unexpanded (written back as an expandable registry value).
    param([string]$BinDir)
    $current = ''
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
        if ($null -ne $key) {
            try { $current = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $key.Close() }
        }
    } catch {
        return "failed: could not read your user PATH ($($_.Exception.Message))"
    }
    $new = Pv-AddToPath $current $BinDir
    if ($new -eq $current) { return 'present' }
    try {
        if ($current -match '%') {
            $wk = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
            try { $wk.SetValue('Path', $new, [Microsoft.Win32.RegistryValueKind]::ExpandString) } finally { $wk.Close() }
        } else {
            [Environment]::SetEnvironmentVariable('Path', $new, 'User')   # also tells running programs about the change
        }
        return 'added'
    } catch {
        return "failed: $($_.Exception.Message)"
    }
}

# ---- the installer ------------------------------------------------------------------------------------------------
function Pv-Main {
    $ErrorActionPreference = 'Stop'
    try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
    $custom = [bool]$env:PROVENANT_SRC
    $wheelName = "provenant_agent_shield-$PvVersion-py3-none-any.whl"
    $src = if ($custom) { $env:PROVENANT_SRC } else { "https://github.com/MithunSidhaarth/provenant/raw/main/dist/$wheelName" }
    $binDir = if ($env:PROVENANT_BIN) { $env:PROVENANT_BIN } else { Join-Path $HOME '.provenant\bin' }
    $work = Join-Path ([IO.Path]::GetTempPath()) ('provenant-' + [guid]::NewGuid().ToString('N'))

    Write-Host ""
    Write-Host "  $PvDia " -ForegroundColor Magenta -NoNewline
    Write-Host "provenant $PvVersion" -NoNewline
    Write-Host "  $PvDot a firewall between AI agents and their tools" -ForegroundColor DarkGray
    Write-Host ""
    try {
        Pv-Step 1 'Finding Python 3.10+'
        $found = Pv-FindPython
        if ($null -eq $found.Python) {
            $why = if ($found.Rejected.Count -gt 0) { ($found.Rejected -join '; ') + '. ' } else { 'No working Python was found. ' }
            Pv-Fail ('Python 3.10 or newer is required. ' + $why) 'Install it with: winget install Python.Python.3.12   (or from https://www.python.org/downloads/ , ticking "Add python.exe to PATH"), then open a new PowerShell window and run this again.'
            return 1
        }
        $py = $found.Python
        Pv-Done "Python $($py.Version)  $($py.Path)"

        Pv-Step 2 'Getting the wheel'
        New-Item -ItemType Directory -Force -Path $work | Out-Null
        $wheel = Join-Path $work $wheelName
        if ($src -match '^https?://') {
            if (-not $custom -and $src -notmatch '^https://') { Pv-Fail 'Refusing a non-HTTPS download.' $null; return 1 }
            $err = Pv-Download $src $wheel
            if ($err) { Pv-Fail "Could not download $src" ("$err  Check your connection or proxy, then run this again. If it keeps failing, see https://github.com/MithunSidhaarth/provenant/blob/main/docs/REAL_GUARD.md") ; return 1 }
        } else {
            if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Pv-Fail "PROVENANT_SRC does not exist: $src" $null; return 1 }
            Copy-Item -LiteralPath $src -Destination $wheel
        }
        $bad = Pv-CheckWheel $py.Path $wheel $work
        if ($bad) { Pv-Fail "The downloaded file is not a valid Provenant $PvVersion wheel: $bad" 'Nothing was installed. If a sign-in or error page was saved instead, the release file is not published at that address yet.'; return 1 }
        if (-not $custom) {
            $actual = (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $PvWheelSha256) { Pv-Fail 'The wheel does not match the checksum pinned in this installer.' "expected $PvWheelSha256`n    got      $actual`n    Nothing was installed." ; return 1 }
            Pv-Done "wheel verified (SHA-256 $($actual.Substring(0, 12))...)"
        } else {
            Pv-Done 'custom wheel accepted (checksum pin skipped)'
        }

        Pv-Step 3 'Installing Provenant'
        $pipArgs = @('-m', 'pip', 'install', '--disable-pip-version-check', '--no-warn-script-location', '--force-reinstall', '--no-deps')
        if (-not $py.InVenv) { $pipArgs += '--user' }
        $pipArgs += $wheel
        $r = Pv-Native $py.Path $pipArgs
        $log = Join-Path ([IO.Path]::GetTempPath()) 'provenant-install.log'
        try { Set-Content -LiteralPath $log -Value $r.Out -Encoding UTF8 } catch { }
        if ($r.Code -ne 0) {
            Pv-Fail "pip could not install Provenant (exit code $($r.Code))." "Last lines of pip output (full log: $log):"
            $r.Out | Select-Object -Last 12 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            return 1
        }
        $chk = Pv-Native $py.Path @('-c', $PvImportCode) $work
        $seen = (($chk.Out | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }) | Select-Object -Last 1)
        if ($chk.Code -ne 0 -or $seen -ne $PvVersion) {
            Pv-Fail "Provenant installed but could not be imported at version $PvVersion (got: $seen)." "Run: `"$($py.Path)`" -m pip uninstall provenant-agent-shield   and run this installer again."
            return 1
        }
        Pv-Done "provenant $seen for $env:USERNAME (no admin needed)"

        Pv-Step 4 'Adding the command'
        $err = Pv-WriteWrapper $binDir $py.Path
        if ($err) { Pv-Fail "Could not create the provenant command: $err" "Provenant itself is installed. Run it with: `"$($py.Path)`" -m provenant status"; return 1 }
        $cmd = Join-Path $binDir 'provenant.cmd'
        $t = Pv-Native $cmd @('--version') $work
        if ($t.Code -ne 0 -or (($t.Out -join ' ') -notmatch [regex]::Escape($PvVersion))) {
            Pv-Fail 'The provenant command was created but did not run.' "Output: $($t.Out -join ' ')   Run Provenant with: `"$($py.Path)`" -m provenant status"
            return 1
        }
        $pathResult = Pv-SetUserPath $binDir
        $sessionNew = Pv-AddToPath $env:Path $binDir
        if ($sessionNew -ne $env:Path) { $env:Path = $sessionNew }
        if ($pathResult -eq 'added') { Pv-Done "added $binDir to your user PATH; new terminals need no extra steps" }
        elseif ($pathResult -eq 'present') { Pv-Done "$binDir was already on your user PATH" }
        else {
            Pv-Done 'works in this window; your PATH was not changed'
            Write-Host "      $pathResult" -ForegroundColor Yellow
            Write-Host "      In new windows run it as: `"$cmd`"   (or add $binDir to PATH in Settings > Environment Variables)" -ForegroundColor Yellow
        }

        Pv-Step 5 'Looking for AI clients'
        Write-Host ""
        if ($env:PROVENANT_NO_SETUP) {
            Write-Host "  Skipped the client check (PROVENANT_NO_SETUP is set)." -ForegroundColor DarkGray
        } else {
            # Never run an interactive command here: this function's output is captured, which hides prompts.
            $plan = Pv-RunTimed $py.Path '-m agentshield.cli setup --dry-run' 30
            if ($plan.TimedOut) {
                Write-Host "  The client check took longer than 30 seconds and was stopped." -ForegroundColor Yellow
            } elseif ($plan.Out.Trim()) {
                foreach ($line in ($plan.Out -split "`r?`n")) { Write-Host $line }
            }
            Write-Host "  Nothing has been changed yet: Provenant is installed but NOT protecting any client." -ForegroundColor Yellow
            Write-Host "  To apply the plan, run:  provenant setup   (it shows the plan again and asks first)" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  Next:  provenant verify   (safe enforcement test)     then   provenant status" -ForegroundColor White
        Write-Host "  Installed is not the same as protected: status shows Configured, Connected and Verified separately." -ForegroundColor DarkGray
        Write-Host "  If 'provenant' is not recognized, open a new PowerShell window, or run:  `"$($py.Path)`" -m provenant verify" -ForegroundColor DarkGray
        Write-Host ""
        return 0
    } catch {
        Pv-Fail "Unexpected error: $($_.Exception.Message)" 'Provenant may be partly installed: run  py -m provenant doctor  to see what is in place. Please report this at https://github.com/MithunSidhaarth/provenant/issues'
        return 1
    } finally {
        if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# PROVENANT_INSTALL_LIB=1 loads the functions without installing (used by tests).
if (-not $env:PROVENANT_INSTALL_LIB) {
    $PvExit = @(Pv-Main)[-1]
    if ($PvExit -isnot [int]) { $PvExit = 1 }
    $global:LASTEXITCODE = $PvExit
    Remove-Item -Path 'function:Pv-*' -ErrorAction SilentlyContinue
    Remove-Variable -Name 'Pv*' -ErrorAction SilentlyContinue
    if ($PSCommandPath) { exit $global:LASTEXITCODE }
}

<#
.SYNOPSIS
    Assemble the deliverable: binaries, dependencies, source and documentation.

.DESCRIPTION
    Produces dist\NetMonitor-<version>-win64\ and a matching .zip containing:

      netmon.exe          the release build (no external runtime required)
      gui/netmon_gui.py    graphical front-end (needs Python 3.8+ with tkinter)
      run-netmon.cmd      launcher that requests elevation
      install-npcap.cmd   installs the bundled Npcap driver if it is missing
      tools\              testapp.exe (verification target), etwprobe.exe
      deps\               the Npcap installer, so a clean machine can be set up
      source\             the complete, buildable crate
      scripts\            install / build / package / verify helpers
      docs\               README, manual, test report

.PARAMETER Version
    Version string baked into the folder name. Defaults to the Cargo version.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\package.ps1
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [string]$Version,
    [switch]$SkipZip
)

$ErrorActionPreference = 'Stop'

if (-not $ProjectRoot) { $ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$ProjectRoot = (Resolve-Path $ProjectRoot).Path

$manifest = Join-Path $ProjectRoot 'netmon\Cargo.toml'
if (-not $Version) {
    $line = Select-String -Path $manifest -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    $Version = if ($line) { $line.Matches[0].Groups[1].Value } else { '0.0.0' }
}

$targetDir = Join-Path $ProjectRoot '.cache\target\release'
$stage = Join-Path $ProjectRoot 'dist'
$name = "NetMonitor-$Version-win64"
$root = Join-Path $stage $name
$zipPath = Join-Path $stage "$name.zip"

Write-Host "==> packaging $name" -ForegroundColor Cyan

foreach ($exe in @('netmon.exe', 'testapp.exe', 'etwprobe.exe')) {
    if (-not (Test-Path (Join-Path $targetDir $exe))) {
        throw "$exe not found in $targetDir -- run scripts\build.ps1 first"
    }
}

# Runtime data that lives beside the executable is user data, not a build
# artifact: a rebuild must not throw it away, and it must not travel in the zip.
# `netmon-data` names the sites this machine visited; `hosts-backups` holds full
# copies of the system hosts file.
$keep = @{}
foreach ($dirName in @('netmon-data', 'hosts-backups')) {
    $src = Join-Path $root $dirName
    if (Test-Path $src) {
        $tmp = Join-Path $env:TEMP ("netmon-keep-$dirName-" + [guid]::NewGuid().ToString('N'))
        Copy-Item $src $tmp -Recurse
        $keep[$dirName] = $tmp
    }
}

if (Test-Path $root) { Remove-Item $root -Recurse -Force }
New-Item -ItemType Directory -Force -Path $root, "$root\tools", "$root\deps", "$root\docs", "$root\scripts", "$root\gui" | Out-Null

# --- binaries ---------------------------------------------------------------
Copy-Item (Join-Path $targetDir 'netmon.exe') $root
foreach ($t in @('testapp.exe', 'etwprobe.exe')) {
    Copy-Item (Join-Path $targetDir $t) "$root\tools"
}
Write-Host "    binaries copied"

# --- Npcap installer --------------------------------------------------------
$npcap = Get-ChildItem (Join-Path $ProjectRoot '.cache\dl') -Recurse -Filter 'npcap-*.exe' -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($npcap) {
    Copy-Item $npcap.FullName "$root\deps"
    $npcapName = $npcap.Name
    Write-Host "    bundled $npcapName"
}
else {
    $npcapName = 'npcap-1.79.exe'
    Write-Warning "no Npcap installer cached; deps\ will be empty. Run scripts\install.ps1."
}

# --- graphical front-end ----------------------------------------------------
# Pure-stdlib Python (tkinter). The capture engine stays in Rust; this is only
# the window, and it talks to netmon.exe over a documented JSON stream.
Copy-Item (Join-Path $ProjectRoot 'gui/netmon_gui.py') "$root\gui"
Write-Host "    GUI copied"

# --- source -----------------------------------------------------------------
# The crate is laid out exactly as it is in the repository, so `cargo build`
# works from this folder with no rearrangement.
$srcRoot = Join-Path $root 'source'
New-Item -ItemType Directory -Force -Path $srcRoot | Out-Null
foreach ($item in @('src', '.cargo')) {
    Copy-Item (Join-Path $ProjectRoot "netmon\$item") $srcRoot -Recurse
}
foreach ($item in @('Cargo.toml', 'build.rs', 'README.md')) {
    Copy-Item (Join-Path $ProjectRoot "netmon\$item") $srcRoot -ErrorAction SilentlyContinue
}
Write-Host "    source copied ($((Get-ChildItem $srcRoot -Recurse -File).Count) files)"

# --- scripts and docs -------------------------------------------------------
Copy-Item (Join-Path $ProjectRoot 'scripts\*.ps1') "$root\scripts"
foreach ($d in @('MANUAL.md', 'TEST-REPORT.md')) {
    $p = Join-Path $ProjectRoot "docs\$d"
    if (Test-Path $p) { Copy-Item $p "$root\docs" } else { Write-Warning "missing docs\$d" }
}
if (Test-Path (Join-Path $ProjectRoot 'README.md')) {
    Copy-Item (Join-Path $ProjectRoot 'README.md') $root
    Copy-Item (Join-Path $ProjectRoot 'README.md') "$root\docs"
}
if (Test-Path (Join-Path $ProjectRoot 'LICENSE')) {
    Copy-Item (Join-Path $ProjectRoot 'LICENSE') $root
    Copy-Item (Join-Path $ProjectRoot 'LICENSE') "$root\docs"
}

# --- launchers --------------------------------------------------------------
$runCmd = @"
@echo off
rem NetMonitor launcher.
rem
rem ETW trace sessions and the Npcap driver both require Administrator, so this
rem wrapper elevates. The monitor starts *before* the target application is
rem launched, which is what guarantees the first query is captured.
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
    exit /b
)

set NETMON_ARGS=%*
if "%NETMON_ARGS%"=="" (
    echo.
    echo   This build has no terminal interface. Use one of:
    echo.
    echo     run-netmon-gui.cmd                                     graphical window
    echo     run-netmon.cmd --app "C:\Path\To\App.exe"             headless, prints records
    echo     run-netmon.cmd --app "C:\Path\To\App.exe" --duration 30 --export out.csv
    echo.
    echo   Full documentation: docs\MANUAL.md
    echo.
    exit /b 2
)

rem Use an explicit path: cmd only searches the current directory when
rem NoDefaultCurrentDirectoryInExePath is unset, which hardened systems
rem routinely set.
"%~dp0netmon.exe" %NETMON_ARGS%
set RC=%errorlevel%
if %RC% neq 0 (
    echo.
    echo netmon exited with code %RC%
    pause
)
endlocal
"@
Set-Content -Path (Join-Path $root 'run-netmon.cmd') -Value $runCmd -Encoding ASCII

$npcapCmd = @"
@echo off
rem Install the Npcap packet capture driver, silently.
rem
rem NetMonitor's primary source (ETW) needs no driver; this is required only
rem for the packet-capture supplement that catches applications with their own
rem DNS resolver, and for TLS SNI recovery.
rem
rem The installer places the kernel driver in %SystemRoot%\System32\drivers --
rem Windows requires it to live there to load at all -- and the user-mode DLLs
rem in %SystemRoot%\System32. That is roughly 1.6 MB on the system drive and is
rem not configurable; see docs\MANUAL.md, "Disk layout".
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

if not exist "%~dp0deps\$npcapName" (
    echo ERROR: deps\$npcapName not found.
    exit /b 1
)

echo Installing Npcap from deps\$npcapName ...
"%~dp0deps\$npcapName" /S /winpcap_mode=yes /loopback_support=yes /dot11_support=yes
if %errorlevel% neq 0 (
    echo Npcap installer exited with %errorlevel%
    exit /b %errorlevel%
)

sc query npcap | findstr /i "RUNNING" >nul
if %errorlevel% equ 0 (
    echo Npcap driver is running.
) else (
    echo Installer finished but the driver is not running.
    echo See %SystemRoot%\System32\Npcap\NPFInstall.log
)
endlocal
"@
Set-Content -Path (Join-Path $root 'install-npcap.cmd') -Value $npcapCmd -Encoding ASCII

$guiCmd = @"
@echo off
rem Launch the graphical front-end.
rem
rem The window is Python with tkinter, standard library only. The capture
rem engine is netmon.exe next to this file. The GUI asks for elevation itself,
rem so this wrapper only has to find a Python interpreter.
rem
rem Arguments are forwarded verbatim. For paths containing spaces it is easier
rem to start the GUI with no arguments and pick the target with the Browse
rem button, because cmd re-parses quoted arguments.
setlocal
cd /d "%~dp0"

set NETMON_PY=
where pythonw.exe >nul 2>&1 && set NETMON_PY=pythonw.exe
if not defined NETMON_PY (
    where py.exe >nul 2>&1 && set NETMON_PY=py.exe -w
)

if not defined NETMON_PY (
    echo.
    echo   Python 3 was not found on PATH.
    echo.
    echo   The graphical interface needs Python with tkinter. Install Python 3
    echo   from python.org and tick the box that adds it to PATH, or use the
    echo   headless launcher instead:  run-netmon.cmd --app "..."
    echo.
    pause
    exit /b 1
)

rem No `start` here: it re-parses the command line and shreds quoted arguments.
rem pythonw.exe has no console, so this call returns immediately anyway.
%NETMON_PY% "%~dp0gui\netmon_gui.py" %*
endlocal
"@
Set-Content -Path (Join-Path $root 'run-netmon-gui.cmd') -Value $guiCmd -Encoding ASCII

# --- version stamp ----------------------------------------------------------
# The rustup shim needs these two variables to find the toolchain; without them
# `rustc --version` fails and the stamp silently says "n/a".
$rustcVersion = 'n/a'
$rustcExe = Join-Path $ProjectRoot '.toolchain\cargo\bin\rustc.exe'
if (Test-Path $rustcExe) {
    $env:RUSTUP_HOME = Join-Path $ProjectRoot '.toolchain\rustup'
    $env:CARGO_HOME = Join-Path $ProjectRoot '.toolchain\cargo'
    try {
        $rustcVersion = (& $rustcExe --version 2>$null) -replace '^rustc\s+', ''
    } catch {
        $rustcVersion = 'n/a'
    }
}
if (-not $rustcVersion) { $rustcVersion = 'n/a' }

$version = @"
NetMonitor $Version  (win64)
built   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
rustc   : $rustcVersion

Quick start
-----------
  1. run-netmon-gui.cmd                                          (graphical window)
  2. run-netmon.cmd --app "C:\Path\To\App.exe"                   (headless records)
  3. run-netmon.cmd --app "C:\Path\To\App.exe" --duration 30 --export out.csv
  4. install-npcap.cmd                                           (add packet capture)

Full documentation: docs\MANUAL.md
"@
Set-Content -Path (Join-Path $root 'VERSION.txt') -Value $version -Encoding UTF8

# --- summary and zip --------------------------------------------------------
$files = Get-ChildItem $root -Recurse -File
$size = [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
Write-Host "    staged $($files.Count) files, $size MB" -ForegroundColor Green

if (-not $SkipZip) {
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path $root -DestinationPath $zipPath -CompressionLevel Optimal
    $zipMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Host "    archive: $zipPath ($zipMb MB)" -ForegroundColor Green
}

# Put the user's runtime data back after the archive is made, so it survives the
# rebuild but never travels in the zip.
foreach ($dirName in $keep.Keys) {
    Copy-Item $keep[$dirName] (Join-Path $root $dirName) -Recurse -Force
    Remove-Item $keep[$dirName] -Recurse -Force
    Write-Host "    kept $dirName\ (not in the archive)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "$root" -ForegroundColor White
exit 0

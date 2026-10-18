<#
.SYNOPSIS
    Build a single self-contained NetMonitor.exe (no Python, no .cmd launcher).

.DESCRIPTION
    The portable folder build (scripts\package.ps1) stays as it is: a folder with
    netmon.exe, the Python GUI source and launchers. This script produces the
    other shape of deliverable -- one windowed executable that carries the Python
    runtime, the GUI, the Rust engine and the Npcap installer inside it:

      dist\NetMonitor-<version>-portable.exe
      dist\NetMonitor-<version>-portable.zip   (exe + LICENSE + README)

    PyInstaller and its dependencies are installed into .toolenv\ in the project
    folder. Nothing is installed system-wide, and .toolenv is git-ignored.

.PARAMETER ProjectRoot
    Repository root. Defaults to the parent of this script's folder.

.PARAMETER Version
    Version in the file name. Defaults to the Cargo package version.

.PARAMETER Engine
    The release netmon.exe to embed. Defaults to .cache\target\release\netmon.exe.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\package-exe.ps1
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [string]$Version,
    [string]$Engine
)

$ErrorActionPreference = 'Stop'

if (-not $ProjectRoot) {
    $ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
$ProjectRoot = (Resolve-Path $ProjectRoot).Path

$manifest = Join-Path $ProjectRoot 'netmon\Cargo.toml'
if (-not $Version) {
    $line = Select-String -Path $manifest -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    $Version = if ($line) { $line.Matches[0].Groups[1].Value } else { '0.0.0' }
}

if (-not $Engine) { $Engine = Join-Path $ProjectRoot '.cache\target\release\netmon.exe' }
if (-not (Test-Path $Engine)) {
    throw "engine not found: $Engine -- run scripts\build.ps1 first"
}
$Engine = (Resolve-Path $Engine).Path

# The installer is only an aid for a clean machine; the build still works
# without it, but then the exe cannot set up a machine that lacks Npcap.
$npcap = Get-ChildItem (Join-Path $ProjectRoot '.cache\dl') -Recurse -Filter 'npcap-*.exe' `
    -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $npcap) {
    Write-Warning "no Npcap installer cached under .cache\dl; the exe will ask the user to install Npcap manually."
} else {
    Write-Host "==> embedding $($npcap.Name)" -ForegroundColor DarkGray
}

# --- local Python environment ------------------------------------------------
# A venv turned out to be unreliable on this machine (its launcher could not
# find pyvenv.cfg), so the build uses what is portable anyway: a private
# site-packages directory in the project, fed by `pip --target`. Nothing is
# installed system-wide, and everything lives under .toolenv\.
$python = (Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $python) {
    throw "Python 3 was not found on PATH; install it first"
}
$localSite = Join-Path $ProjectRoot '.toolenv\site-packages'
if (-not (Test-Path (Join-Path $localSite 'PyInstaller'))) {
    Write-Host "==> installing PyInstaller into .toolenv\site-packages" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $localSite | Out-Null
    & $python -m pip install --quiet --upgrade --target $localSite "pyinstaller>=6.10,<7"
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller install failed" }
}
$env:PYTHONPATH = $localSite + ';' + $env:PYTHONPATH
$env:PYTHONUTF8 = '1'
$env:PIP_DISABLE_PIP_VERSION_CHECK = '1'
$pyiVersion = (& $python -c "import PyInstaller; print(PyInstaller.__version__)") 2>$null
Write-Host "    PyInstaller $pyiVersion (local)" -ForegroundColor DarkGray

# --- build ------------------------------------------------------------------
$gui = Join-Path $ProjectRoot 'gui\netmon_gui.py'
$work = Join-Path $ProjectRoot '.cache\pyinstaller\build'
$specDir = Join-Path $ProjectRoot '.cache\pyinstaller'
$onefileDir = Join-Path $ProjectRoot '.cache\pyinstaller\dist'
foreach ($d in @($work, $specDir, $onefileDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

Write-Host "==> building one-file NetMonitor.exe" -ForegroundColor Cyan
$pyiArgs = @(
    '--noconfirm', '--clean', '--onefile', '--windowed',
    '--name', 'NetMonitor',
    '--distpath', $onefileDir,
    '--workpath', $work,
    '--specpath', $specDir,
    '--add-binary', "$Engine;.",
    '--exclude-module', 'unittest',
    '--exclude-module', 'pydoc',
    $gui
)
if ($npcap) {
    $pyiArgs = @('--add-binary', "$($npcap.FullName);.") + $pyiArgs
}
& $python -m PyInstaller @pyiArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$built = Join-Path $onefileDir 'NetMonitor.exe'
if (-not (Test-Path $built)) { throw "expected $built" }

# --- verify the bundle actually carries the engine ---------------------------
Write-Host "==> verifying bundle" -ForegroundColor Cyan
$probeOut = Join-Path $env:TEMP ("netmon-selftest-" + [guid]::NewGuid().ToString('N') + '.json')
$proc = Start-Process -FilePath $built `
    -ArgumentList @('--selftest', "`"$probeOut`"") -Wait -PassThru
if (-not (Test-Path $probeOut)) {
    throw "selftest did not write $probeOut (exit $($proc.ExitCode))"
}
$info = Get-Content $probeOut -Raw | ConvertFrom-Json
Write-Host ("    frozen={0} engine={1} exists={2} wpcap={3}" -f `
    $info.frozen, $info.engine, $info.engine_exists, $info.wpcap) -ForegroundColor DarkGray
Remove-Item $probeOut -Force -ErrorAction SilentlyContinue
if (-not $info.engine_exists) { throw "the bundled engine is missing from the one-file build" }

# --- stage and zip -----------------------------------------------------------
$dist = Join-Path $ProjectRoot 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$exeName = "NetMonitor-$Version-portable.exe"
$exePath = Join-Path $dist $exeName
Copy-Item $built $exePath -Force

$zipPath = Join-Path $dist "NetMonitor-$Version-portable.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
$stage = Join-Path $env:TEMP ("netmon-portable-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item $exePath $stage
Copy-Item (Join-Path $ProjectRoot 'LICENSE') (Join-Path $stage 'LICENSE.txt')
Copy-Item (Join-Path $ProjectRoot 'README.md') (Join-Path $stage 'README.md')
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal
Remove-Item $stage -Recurse -Force

$hash = (Get-FileHash $exePath -Algorithm SHA256).Hash
$mb = [math]::Round((Get-Item $exePath).Length / 1MB, 2)
Write-Host ""
Write-Host "  $exePath  ($mb MB)" -ForegroundColor Green
Write-Host "  SHA256 $hash" -ForegroundColor DarkGray
Write-Host "  $zipPath" -ForegroundColor Green
exit 0

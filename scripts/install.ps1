<#
.SYNOPSIS
    Install everything NetMonitor needs, keeping caches on a non-system drive.

.DESCRIPTION
    Installs, idempotently:

      * the Rust toolchain (rustup) with RUSTUP_HOME and CARGO_HOME under the
        project drive, so nothing lands in %USERPROFILE%\.cargo;
      * the Npcap SDK (headers + wpcap.lib) used at build time;
      * the Npcap runtime (driver + DLLs) via its silent installer.

    Every download is cached under <Project>\\.cache\\dl, and every extracted
    artefact under <Project>\\.cache\\deps, so re-running is cheap and a failed
    run can be resumed.

    NOTE ON NPCAY'S INSTALL LOCATION: Npcap's own installer decides where the
    user-mode DLLs and the kernel driver go; it does not honour a destination
    override. The kernel driver *must* live in %SystemRoot%\\System32\\drivers to
    load at all -- that is a Windows requirement, not a choice -- and the DLLs
    go to %SystemRoot%\\System32 (WinPcap-compatible mode) or
    %SystemRoot%\\System32\\Npcap. Everything this script controls (toolchain,
    caches, build output, the packaged deliverable) stays on the project drive.
    See the manual's "Disk layout" section for the measured sizes.

.PARAMETER ProjectRoot
    Project directory. Defaults to the parent of this script.

.PARAMETER SkipNpcapRuntime
    Do not install the Npcap driver (useful when it is already present).

.PARAMETER SkipRust
    Do not install the Rust toolchain.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [switch]$SkipNpcapRuntime,
    [switch]$SkipRust,
    [string]$NpcapVersion = '1.79',
    [string]$NpcapSdkVersion = '1.15'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is far faster without it

if (-not $ProjectRoot) { $ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$ProjectRoot = (Resolve-Path $ProjectRoot).Path

$CacheDl = Join-Path $ProjectRoot '.cache\dl'
$CacheDeps = Join-Path $ProjectRoot '.cache\deps'
$Toolchain = Join-Path $ProjectRoot '.toolchain'

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host "NetMonitor installer" -ForegroundColor White
Write-Host "project root : $ProjectRoot"
Write-Host "caches       : $CacheDl"
Write-Host "toolchain    : $Toolchain"
Write-Host ""

$elevated = Test-Administrator
Write-Host "elevated     : $elevated"
if (-not $elevated) {
    Write-Warn "Not running as Administrator. Rust and the SDK can still be installed,"
    Write-Warn "but the Npcap driver cannot. Re-run from an elevated prompt for that."
}
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Rust toolchain, off the system drive
# ---------------------------------------------------------------------------
if (-not $SkipRust) {
    Write-Step "Rust toolchain"
    $env:RUSTUP_HOME = Join-Path $Toolchain 'rustup'
    $env:CARGO_HOME = Join-Path $Toolchain 'cargo'
    New-Item -ItemType Directory -Force -Path $env:RUSTUP_HOME, $env:CARGO_HOME | Out-Null

    $cargo = Join-Path $env:CARGO_HOME 'bin\cargo.exe'
    if (Test-Path $cargo) {
        Write-Ok "already installed: $(& $cargo --version)"
    }
    else {
        $dl = Join-Path $CacheDl 'rustup'
        New-Item -ItemType Directory -Force -Path $dl | Out-Null
        $init = Join-Path $dl 'rustup-init.exe'
        if (-not (Test-Path $init)) {
            Write-Ok "downloading rustup-init.exe"
            Invoke-WebRequest -UseBasicParsing -Uri `
                'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' `
                -OutFile $init
        }
        Write-Ok "installing toolchain into $Toolchain (this takes a few minutes)"
        & $init -y --no-modify-path --default-host x86_64-pc-windows-msvc `
            --default-toolchain stable --profile minimal
        if ($LASTEXITCODE -ne 0) { throw "rustup-init failed with $LASTEXITCODE" }
    }
    Write-Ok "RUSTUP_HOME=$env:RUSTUP_HOME"
    Write-Ok "CARGO_HOME=$env:CARGO_HOME"
}

# ---------------------------------------------------------------------------
# 2. MSVC build tools (detected, never installed silently)
# ---------------------------------------------------------------------------
Write-Step "MSVC build tools"
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = $null
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null
}
if ($vsPath) {
    Write-Ok "found: $vsPath"
}
else {
    Write-Warn "No Visual Studio C++ toolset found."
    Write-Warn "Install 'Visual Studio Build Tools 2022' with the 'Desktop development with C++'"
    Write-Warn "workload from https://visualstudio.microsoft.com/downloads/ and re-run."
    Write-Warn "The linker cannot be pointed at a non-system drive; about 4 GB goes to C:."
}

# ---------------------------------------------------------------------------
# 3. Npcap SDK (build-time only)
# ---------------------------------------------------------------------------
Write-Step "Npcap SDK $NpcapSdkVersion"
$sdkDir = Join-Path $CacheDeps 'npcap-sdk'
if (Test-Path (Join-Path $sdkDir 'Lib\x64\wpcap.lib')) {
    Write-Ok "already extracted: $sdkDir"
}
else {
    New-Item -ItemType Directory -Force -Path $CacheDl, $sdkDir | Out-Null
    $zip = Join-Path $CacheDl "npcap-sdk-$NpcapSdkVersion.zip"
    if (-not (Test-Path $zip)) {
        Write-Ok "downloading npcap-sdk-$NpcapSdkVersion.zip"
        Invoke-WebRequest -UseBasicParsing -Uri `
            "https://npcap.com/dist/npcap-sdk-$NpcapSdkVersion.zip" -OutFile $zip
    }
    Expand-Archive -Path $zip -DestinationPath $sdkDir -Force
    if (-not (Test-Path (Join-Path $sdkDir 'Lib\x64\wpcap.lib'))) {
        throw "wpcap.lib not found after extracting $zip"
    }
    Write-Ok "extracted to $sdkDir"
}

# ---------------------------------------------------------------------------
# 4. Npcap runtime (driver + DLLs)
# ---------------------------------------------------------------------------
if (-not $SkipNpcapRuntime) {
    Write-Step "Npcap runtime $NpcapVersion"
    $svc = Get-Service -Name npcap -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Ok "driver already loaded (service 'npcap' is Running)"
    }
    elseif (-not $elevated) {
        Write-Warn "skipped: installing the driver requires Administrator"
    }
    else {
        New-Item -ItemType Directory -Force -Path (Join-Path $CacheDl 'npcap') | Out-Null
        $exe = Join-Path $CacheDl "npcap\npcap-$NpcapVersion.exe"
        if (-not (Test-Path $exe)) {
            Write-Ok "downloading npcap-$NpcapVersion.exe"
            Invoke-WebRequest -UseBasicParsing -Uri "https://npcap.com/dist/npcap-$NpcapVersion.exe" `
                -OutFile $exe
        }
        Write-Ok "running the silent installer"
        # /winpcap_mode=yes places wpcap.dll in System32 so binaries built
        # against the SDK resolve it without a PATH entry.
        # NOTE: do NOT pass /D=<path> -- it is not honoured and makes the
        # installer exit with code 2.
        $p = Start-Process -FilePath $exe -Wait -PassThru -ArgumentList `
            '/S', '/winpcap_mode=yes', '/loopback_support=yes', '/dot11_support=yes'
        if ($p.ExitCode -ne 0) { throw "npcap installer exited with $($p.ExitCode)" }
        $svc = Get-Service -Name npcap -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Ok "driver installed and running"
        }
        else {
            Write-Warn "installer succeeded but service 'npcap' is not running;"
            Write-Warn "check %SystemRoot%\System32\Npcap\NPFInstall.log"
        }
    }
}

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Step "Disk usage"
foreach ($p in @($Toolchain, $CacheDl, $CacheDeps)) {
    if (Test-Path $p) {
        $mb = [math]::Round(((Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum) / 1MB, 1)
        Write-Ok ("{0,-48} {1,8} MB" -f $p, $mb)
    }
}
Write-Host ""
Write-Host "Next: powershell -ExecutionPolicy Bypass -File scripts\build.ps1" -ForegroundColor White

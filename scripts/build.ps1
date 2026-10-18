<#
.SYNOPSIS
    Build NetMonitor from source.

.DESCRIPTION
    Sets up the off-system-drive toolchain environment, resolves the Npcap SDK,
    runs the test suite and produces release binaries under .cache\target\release.

.PARAMETER Configuration
    'release' (default) or 'debug'.

.PARAMETER SkipTests
    Build without running the unit tests first.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\build.ps1
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [ValidateSet('release', 'debug')][string]$Configuration = 'release',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'

if (-not $ProjectRoot) { $ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$ProjectRoot = (Resolve-Path $ProjectRoot).Path

$env:RUSTUP_HOME = Join-Path $ProjectRoot '.toolchain\rustup'
$env:CARGO_HOME = Join-Path $ProjectRoot '.toolchain\cargo'
$env:CARGO_TARGET_DIR = Join-Path $ProjectRoot '.cache\target'
$env:NETMON_NPCAP_SDK = Join-Path $ProjectRoot '.cache\deps\npcap-sdk'
$env:PATH = (Join-Path $env:CARGO_HOME 'bin') + ';' + $env:PATH

$cargo = Join-Path $env:CARGO_HOME 'bin\cargo.exe'
if (-not (Test-Path $cargo)) {
    throw "cargo not found at $cargo -- run scripts\install.ps1 first"
}

$manifest = Join-Path $ProjectRoot 'netmon\Cargo.toml'
if (-not (Test-Path $manifest)) { throw "no Cargo.toml at $manifest" }

if (-not (Test-Path (Join-Path $env:NETMON_NPCAP_SDK 'Lib\x64\wpcap.lib'))) {
    Write-Warning "wpcap.lib not found under $env:NETMON_NPCAP_SDK; the link step will fail."
    Write-Warning "Run scripts\install.ps1 to fetch the Npcap SDK."
}

Write-Host "==> building ($Configuration)" -ForegroundColor Cyan

if (-not $SkipTests) {
    Write-Host "==> cargo test" -ForegroundColor Cyan
    & $cargo test --manifest-path $manifest --bins
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}

$flag = if ($Configuration -eq 'release') { '--release' } else { '' }
$args = @('build', '--manifest-path', $manifest, '--bin', 'netmon', '--bin', 'testapp', '--bin', 'etwprobe')
if ($flag) { $args += $flag }

& $cargo @args
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$outDir = Join-Path $env:CARGO_TARGET_DIR $Configuration
Write-Host ""
Write-Host "==> binaries in $outDir" -ForegroundColor Cyan
Get-ChildItem $outDir -Filter *.exe |
    Where-Object { $_.Name -in @('netmon.exe', 'testapp.exe', 'etwprobe.exe') } |
    ForEach-Object { Write-Host ("    {0,-16} {1,10:N0} bytes" -f $_.Name, $_.Length) }

Write-Host ""
Write-Host "Next: powershell -ExecutionPolicy Bypass -File scripts\package.ps1" -ForegroundColor White

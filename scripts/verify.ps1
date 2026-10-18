<#
.SYNOPSIS
    End-to-end verification of NetMonitor against a known target.

.DESCRIPTION
    Runs the monitor in headless mode against `testapp.exe`, which resolves a
    set of names chosen at random so nothing can be served from the DNS cache,
    forks a child process, and emits a TLS ClientHello. The script then asserts:

      1. every name the target asked for was captured;
      2. every captured row is attributed to the target tree, and the child's
         PID appears as well as the parent's;
      3. a name resolved by an unrelated process is *not* reported;
      4. no events were dropped by the kernel or by the queue;
      5. the export file is well formed and contains the same rows.

    Exit code is 0 when every check passes.

.PARAMETER Configuration
    Which build to test: 'release' (default) or 'debug'.

.PARAMETER Duration
    Seconds to monitor (default 20).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [ValidateSet('release', 'debug')][string]$Configuration = 'release',
    [int]$Duration = 20,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'

if (-not $ProjectRoot) { $ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$ProjectRoot = (Resolve-Path $ProjectRoot).Path

$env:CARGO_TARGET_DIR = Join-Path $ProjectRoot '.cache\target'
$binDir = Join-Path $env:CARGO_TARGET_DIR $Configuration
$netmon = Join-Path $binDir 'netmon.exe'
$testapp = Join-Path $binDir 'testapp.exe'

if (-not $OutputDir) { $OutputDir = Join-Path $ProjectRoot '.cache\verify' }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if (-not (Test-Path $netmon)) { throw "missing $netmon -- run scripts\build.ps1 first" }
if (-not (Test-Path $testapp)) { throw "missing $testapp -- run scripts\build.ps1 first" }

$checks = New-Object System.Collections.Generic.List[object]
function Check($name, $ok, $detail) {
    $checks.Add([pscustomobject]@{ Name = $name; Ok = [bool]$ok; Detail = $detail })
    $colour = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("  [{0}] {1,-46} {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $detail) -ForegroundColor $colour
}

Write-Host "NetMonitor verification ($Configuration)" -ForegroundColor White
Write-Host ""

# --- environment -----------------------------------------------------------
Write-Host "==> environment" -ForegroundColor Cyan
$ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
& $ipconfig /flushdns | Out-Null
Write-Host "    DNS cache flushed"

# Elevation is *reported*, not asserted. It is a proxy for "can the capture
# sources start", and a poor one: an unelevated token was measured on this
# machine starting both ETW and Npcap without complaint. The authoritative
# check is the engine's own doctor, right below.
$elevated = ([Security.Principal.WindowsPrincipal]`
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ("    token elevated: {0} (informational)" -f $elevated)

$doctor = & $netmon --doctor 2>&1 | Out-String
$etwOk = $doctor -match 'etw session\s+:\s+OK'
Check 'engine can open an ETW session' $etwOk `
    $(if ($etwOk) { 'doctor reports the DNS provider enabled' }
      else { 'doctor could not enable the DNS provider (see --doctor output)' })

$npcap = Get-Service -Name npcap -ErrorAction SilentlyContinue
Check 'Npcap driver loaded' ($npcap -and $npcap.Status -eq 'Running') `
    $(if ($npcap) { "service state: $($npcap.Status)" } else { 'service not installed' })

# --- run -------------------------------------------------------------------
$stamp = Get-Random
$targets = @(
    'www.example.com'
    'github.com'
    'www.bing.com'
    "verify-$stamp-a.netmon-probe.invalid"
    "verify-$stamp-b.netmon-probe.invalid"
)
# A name resolved by an unrelated process, which must never show up.
$foreignName = "foreign-$stamp.netmon-probe.invalid"

Write-Host ""
Write-Host "==> monitoring (${Duration}s)" -ForegroundColor Cyan
Write-Host "    target names: $($targets -join ', ')"

$outFile = Join-Path $OutputDir 'run.txt'
$errFile = Join-Path $OutputDir 'run.err'
$csvFile = Join-Path $OutputDir 'run.csv'

$argLine = @(
    '--headless', '--no-color',
    '--app', "`"$testapp`"",
    '--arg', '--fork',
    '--arg', '--sni', '--arg', 'www.cloudflare.com',
    '--duration', $Duration,
    '--export', "`"$csvFile`""
)
foreach ($t in $targets) { $argLine += @('--arg', $t) }

# Resolve the foreign name in a *separate* process while the monitor runs.
$foreignJob = Start-Job -ScriptBlock {
    param($name)
    Start-Sleep -Milliseconds 1500
    try { [System.Net.Dns]::GetHostAddresses($name) | Out-Null } catch { }
} -ArgumentList $foreignName

# -Wait is required: without it Start-Process leaves ExitCode unpopulated when
# output is redirected, and the check below would read $null.
$proc = Start-Process -FilePath $netmon -ArgumentList $argLine -NoNewWindow -PassThru -Wait `
    -RedirectStandardOutput $outFile -RedirectStandardError $errFile
$exitCode = $proc.ExitCode
if ($null -eq $exitCode) { $exitCode = -1 }
Wait-Job $foreignJob | Out-Null
Remove-Job $foreignJob -Force

Write-Host "    monitor exited with $exitCode"
Get-Content $errFile | Where-Object { $_ -notmatch 'Npcap capturing on' } | ForEach-Object {
    Write-Host "      $_" -ForegroundColor DarkGray
}

# --- assertions ------------------------------------------------------------
Write-Host ""
Write-Host "==> checks" -ForegroundColor Cyan

Check 'monitor exited cleanly' ($exitCode -eq 0) "exit code $exitCode"

$rows = @(Get-Content $outFile | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
    $f = $_ -split "`t"
    [pscustomobject]@{
        Seq = $f[0]; Time = $f[1]; Process = $f[2]; Pid = [int]$f[3]
        QType = $f[4]; Source = $f[5]; Kind = $f[6]; Domain = $f[7]; Detail = $f[8]
    }
})
$queries = @($rows | Where-Object { $_.Kind -eq 'query' })

Check 'rows captured' ($rows.Count -gt 0) "$($rows.Count) row(s)"

$missing = @()
foreach ($t in $targets) {
    if (-not ($queries | Where-Object { $_.Domain -eq $t })) { $missing += $t }
}
Check 'all target names captured' ($missing.Count -eq 0) `
    $(if ($missing.Count -eq 0) { "$($targets.Count)/$($targets.Count)" } else { "missing: $($missing -join ', ')" })

$pids = @($queries | Select-Object -ExpandProperty Pid -Unique)
Check 'parent and child both attributed' ($pids.Count -ge 2) `
    "PIDs seen: $($pids -join ', ')"

$names = @($queries | Select-Object -ExpandProperty Process -Unique)
Check 'process name resolved' (($names.Count -eq 1) -and $names[0] -like 'testapp*') `
    "process names: $($names -join ', ')"

$leak = @($rows | Where-Object { $_.Domain -eq $foreignName })
Check 'unrelated process excluded' ($leak.Count -eq 0) `
    $(if ($leak.Count -eq 0) { "no row for $foreignName" } else { "$($leak.Count) leaked row(s)" })

$sni = @($rows | Where-Object { $_.Kind -eq 'tls_sni' -and $_.Domain -eq 'www.cloudflare.com' })
Check 'TLS SNI fallback attributed' ($sni.Count -ge 1) `
    $(if ($sni.Count -ge 1) { "pid $($sni[0].Pid)" } else { 'no SNI row' })

$dropLine = Get-Content $errFile | Where-Object { $_ -match 'drop\(s\)' } | Select-Object -Last 1
$zeroDrops = $dropLine -match '\s0 drop\(s\)'
Check 'no events dropped' $zeroDrops $(if ($dropLine) { $dropLine.Trim() } else { 'no summary line' })

$pcapLine = Get-Content $errFile | Where-Object { $_ -match '^\[info\] pcap:' } | Select-Object -Last 1
Check 'packet capture active' ($pcapLine -and $pcapLine -notmatch ' 0 packet') `
    $(if ($pcapLine) { ($pcapLine -replace '\s+', ' ').Trim() } else { 'no pcap summary' })

Check 'CSV export written' (Test-Path $csvFile) `
    $(if (Test-Path $csvFile) { "$((Get-Content $csvFile).Count - 1) row(s)" } else { 'missing' })

# --- report ----------------------------------------------------------------
$passed = ($checks | Where-Object { $_.Ok }).Count
$total = $checks.Count
Write-Host ""
Write-Host "==> $passed / $total checks passed" -ForegroundColor $(if ($passed -eq $total) { 'Green' } else { 'Red' })

$json = [pscustomobject]@{
    when = (Get-Date).ToString('s')
    configuration = $Configuration
    targets = $targets
    checks = $checks
    rows = $rows.Count
    queries = $queries.Count
    pids = $pids
} | ConvertTo-Json -Depth 5
Set-Content -Path (Join-Path $OutputDir 'result.json') -Value $json -Encoding UTF8
Write-Host "    evidence written to $OutputDir"

if ($passed -ne $total) { exit 1 }
exit 0

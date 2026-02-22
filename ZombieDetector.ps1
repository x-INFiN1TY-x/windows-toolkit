#Requires -Version 5.1
param(
    [switch]$AutoExport  # For unattended/scheduled runs — scans and exports without interaction
)
<#
.SYNOPSIS
    Advanced Windows Zombie Process Detector & Killer
.DESCRIPTION
    Detects zombie-like processes: hung, orphaned, idle long-runners, hidden resource hogs,
    suspended threads, and ghost services. Interactive menu with kill capabilities.
    Use -AutoExport for unattended scheduled runs.
.NOTES
    Run as Administrator for full visibility.
#>

# ── Config ──
$ExportDir = "$env:USERPROFILE\Desktop\ProcessAudit"
if (!(Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null }

# Processes that are ALWAYS safe to ignore (system-level, expected behavior)
$SafeIgnoreList = @(
    "Idle", "System", "Registry", "Memory Compression", "smss", "csrss",
    "wininit", "winlogon", "lsass", "services", "svchost", "fontdrvhost",
    "dwm", "conhost", "WmiPrvSE", "dllhost", "sihost", "taskhostw",
    "RuntimeBroker", "backgroundTaskHost", "SecurityHealthSystray",
    "ctfmon", "TextInputHost"
)

# ── Detection Functions ──

function Detect-NotResponding {
    Write-Host "`n  [SCAN 1/7] Checking for NOT RESPONDING processes..." -ForegroundColor DarkGray
    $results = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Responding -eq $false -and $_.ProcessName -notin $SafeIgnoreList } catch { $false }
    } | ForEach-Object {
        $mem = [math]::Round($_.WorkingSet64 / 1MB, 1)
        $start = try { $_.StartTime } catch { $null }
        [PSCustomObject]@{
            Type      = "NOT_RESPONDING"
            Severity  = "HIGH"
            Name      = $_.ProcessName
            PID       = $_.Id
            "Mem_MB"  = $mem
            StartTime = if ($start) { $start.ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
            Detail    = "Process is hung / not responding to Windows messages"
            Safe      = $true
        }
    }
    return $results
}

function Detect-Orphaned {
    Write-Host "  [SCAN 2/7] Checking for ORPHANED processes..." -ForegroundColor DarkGray
    $allPids = @{}
    Get-Process | ForEach-Object { $allPids[$_.Id] = $true }
    $results = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ParentProcessId -and
        $_.ParentProcessId -ne 0 -and
        $_.ProcessId -ne 0 -and
        $_.ProcessId -ne 4 -and
        -not $allPids.ContainsKey([int]$_.ParentProcessId) -and
        $_.Name -replace '\.exe$','' -notin $SafeIgnoreList
    } | ForEach-Object {
        [PSCustomObject]@{
            Type      = "ORPHANED"
            Severity  = "MEDIUM"
            Name      = $_.Name
            PID       = $_.ProcessId
            "Mem_MB"  = [math]::Round($_.WorkingSetSize / 1MB, 1)
            StartTime = if ($_.CreationDate) { $_.CreationDate.ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
            Detail    = "Parent PID $($_.ParentProcessId) no longer exists"
            Safe      = $true
        }
    }
    return $results
}

function Detect-IdleLongRunning {
    param([int]$HoursThreshold = 24)
    Write-Host "  [SCAN 3/7] Checking for IDLE LONG-RUNNING processes (>$HoursThreshold hrs, 0 CPU)..." -ForegroundColor DarkGray
    $results = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -notin $SafeIgnoreList -and
        $(try { $_.CPU -eq 0 -and $_.StartTime -and ((Get-Date) - $_.StartTime).TotalHours -gt $HoursThreshold } catch { $false })
    } | ForEach-Object {
        $runtime = (Get-Date) - $_.StartTime
        [PSCustomObject]@{
            Type      = "IDLE_LONGRUN"
            Severity  = "LOW"
            Name      = $_.ProcessName
            PID       = $_.Id
            "Mem_MB"  = [math]::Round($_.WorkingSet64 / 1MB, 1)
            StartTime = $_.StartTime.ToString("yyyy-MM-dd HH:mm")
            Detail    = "Running {0}d {1}h with zero CPU usage" -f $runtime.Days, $runtime.Hours
            Safe      = $true
        }
    }
    return $results
}

function Detect-HiddenResourceHogs {
    param([int]$MemThresholdMB = 50)
    Write-Host "  [SCAN 4/7] Checking for HIDDEN resource hogs (no window, >$($MemThresholdMB)MB)..." -ForegroundColor DarkGray
    $results = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.MainWindowHandle -eq 0 -and
        $_.ProcessName -notin $SafeIgnoreList -and
        $_.WorkingSet64 -gt ($MemThresholdMB * 1MB)
    } | ForEach-Object {
        [PSCustomObject]@{
            Type      = "HIDDEN_HOG"
            Severity  = if ($_.WorkingSet64 -gt 200MB) { "HIGH" } else { "MEDIUM" }
            Name      = $_.ProcessName
            PID       = $_.Id
            "Mem_MB"  = [math]::Round($_.WorkingSet64 / 1MB, 1)
            StartTime = $(try { $_.StartTime.ToString("yyyy-MM-dd HH:mm") } catch { "N/A" })
            Detail    = "No visible window, consuming $([math]::Round($_.WorkingSet64/1MB,1)) MB"
            Safe      = $true
        }
    }
    return $results
}

function Detect-SuspendedThreads {
    Write-Host "  [SCAN 5/7] Checking for processes with ALL SUSPENDED threads..." -ForegroundColor DarkGray
    $results = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -notin $SafeIgnoreList -and $_.Threads.Count -gt 0
    } | Where-Object {
        $suspended = ($_.Threads | Where-Object { $_.WaitReason -eq "Suspended" }).Count
        $suspended -gt 0 -and $suspended -eq $_.Threads.Count
    } | ForEach-Object {
        [PSCustomObject]@{
            Type      = "ALL_SUSPENDED"
            Severity  = "MEDIUM"
            Name      = $_.ProcessName
            PID       = $_.Id
            "Mem_MB"  = [math]::Round($_.WorkingSet64 / 1MB, 1)
            StartTime = $(try { $_.StartTime.ToString("yyyy-MM-dd HH:mm") } catch { "N/A" })
            Detail    = "All $($_.Threads.Count) threads are suspended"
            Safe      = $true
        }
    }
    return $results
}

function Detect-GhostServices {
    Write-Host "  [SCAN 6/7] Checking for GHOST services (stopped but process alive)..." -ForegroundColor DarkGray
    $stoppedSvcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Stopped" -and $_.ServiceType -notlike "*Driver*" }
    $results = @()
    foreach ($svc in $stoppedSvcs) {
        try {
            $wmiSvc = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
            if ($wmiSvc -and $wmiSvc.ProcessId -gt 0) {
                $proc = Get-Process -Id $wmiSvc.ProcessId -ErrorAction SilentlyContinue
                if ($proc -and $proc.ProcessName -ne "svchost") {
                    $results += [PSCustomObject]@{
                        Type      = "GHOST_SERVICE"
                        Severity  = "MEDIUM"
                        Name      = "$($svc.Name) ($($proc.ProcessName))"
                        PID       = $wmiSvc.ProcessId
                        "Mem_MB"  = [math]::Round($proc.WorkingSet64 / 1MB, 1)
                        StartTime = $(try { $proc.StartTime.ToString("yyyy-MM-dd HH:mm") } catch { "N/A" })
                        Detail    = "Service '$($svc.DisplayName)' is stopped but PID $($wmiSvc.ProcessId) still alive"
                        Safe      = $true
                    }
                }
            }
        } catch { }
    }
    return $results
}

function Detect-DuplicateProcesses {
    Write-Host "  [SCAN 7/7] Checking for EXCESSIVE DUPLICATES..." -ForegroundColor DarkGray
    $groups = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -notin $SafeIgnoreList } |
        Group-Object ProcessName |
        Where-Object { $_.Count -gt 10 }
    $results = foreach ($g in $groups) {
        $totalMem = [math]::Round(($g.Group | Measure-Object -Property WorkingSet64 -Sum).Sum / 1MB, 1)
        [PSCustomObject]@{
            Type      = "EXCESSIVE_DUPES"
            Severity  = if ($totalMem -gt 500) { "HIGH" } else { "MEDIUM" }
            Name      = $g.Name
            PID       = ($g.Group | Select-Object -First 1).Id
            "Mem_MB"  = $totalMem
            StartTime = "N/A"
            Detail    = "$($g.Count) instances running, total $totalMem MB — possible leak or runaway spawning"
            Safe      = $false
        }
    }
    return $results
}

# ── Display & Action Functions ──

function Show-ZombieSummary {
    param($Data)
    if (!$Data -or $Data.Count -eq 0) {
        Write-Host "  ┌─ LAST SCAN: ✓ No zombies detected ─────────────────────┐" -ForegroundColor Green
        Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Green
        Write-Host ""
        return
    }
    $totalMem = [math]::Round(($Data | Measure-Object Mem_MB -Sum).Sum, 1)
    $highCount = ($Data | Where-Object { $_.Severity -eq "HIGH" }).Count
    $safeCount = ($Data | Where-Object { $_.Safe }).Count
    Write-Host "  ┌─ LAST SCAN RESULTS ─────────────────────────────────────┐" -ForegroundColor Red
    Write-Host ("  │  Zombies: {0,-4}  HIGH severity: {1,-4}  Safe to kill: {2,-4}   │" -f $Data.Count, $highCount, $safeCount) -ForegroundColor White
    Write-Host ("  │  Memory reclaimable: {0} MB                              │" -f $totalMem) -ForegroundColor Yellow
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Red
    Write-Host ""
}

function Show-Banner {
    param($Data, [switch]$NoClear)
    if (!$NoClear) { Clear-Host }
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║         ZOMBIE PROCESS DETECTOR v3.0                    ║" -ForegroundColor Red
    Write-Host "  ║   Detect · Analyze · Exterminate                        ║" -ForegroundColor Red
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Show-ZombieSummary $Data
}

function Show-Menu {
    Write-Host "  ── SCAN ─────────────────────────────────────────────────" -ForegroundColor DarkRed
    Write-Host "   [1]  Full Scan           — run all 7 detection engines  " -ForegroundColor White
    Write-Host "   [2]  Not Responding      — hung processes               " -ForegroundColor White
    Write-Host "   [3]  Orphaned            — parent process exited        " -ForegroundColor White
    Write-Host "   [4]  Idle Long-Runners   — 0 CPU for hours             " -ForegroundColor White
    Write-Host "   [5]  Hidden Hogs         — no window, high memory       " -ForegroundColor White
    Write-Host "   [6]  Suspended Threads   — all threads frozen           " -ForegroundColor White
    Write-Host "   [7]  Ghost Services      — stopped but still alive      " -ForegroundColor White
    Write-Host "   [8]  Excessive Dupes     — 10+ instances of same proc   " -ForegroundColor White
    Write-Host ""
    Write-Host "  ── TAKE ACTION ──────────────────────────────────────────" -ForegroundColor DarkRed
    Write-Host "   [9]  Kill (interactive)  — pick which zombies to kill   " -ForegroundColor White
    Write-Host "   [10] Kill ALL Safe       — batch kill safe zombies      " -ForegroundColor White
    Write-Host "   [11] Export Report       — save CSV + HTML to Desktop   " -ForegroundColor White
    Write-Host "   [12] Configure           — change detection thresholds  " -ForegroundColor White
    Write-Host ""
    Write-Host "  ── OTHER ────────────────────────────────────────────────" -ForegroundColor DarkRed
    Write-Host "   [?] Help   [0] Exit                                     " -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Help {
    Write-Host "`n  ── QUICK HELP ──" -ForegroundColor Red
    Write-Host "  This tool finds zombie-like processes that waste resources." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Recommended workflow:" -ForegroundColor White
    Write-Host "    1. Run [1] Full Scan — see everything at once" -ForegroundColor DarkGray
    Write-Host "    2. Review the results — HIGH severity items first" -ForegroundColor DarkGray
    Write-Host "    3. Run [9] Kill Interactive — pick specific zombies" -ForegroundColor DarkGray
    Write-Host "    4. Or [10] Kill ALL Safe — batch clean safe ones" -ForegroundColor DarkGray
    Write-Host "    5. Run [11] Export — save a report for your records" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Severity guide:" -ForegroundColor White
    Write-Host "    HIGH   = genuinely problematic, kill recommended" -ForegroundColor Red
    Write-Host "    MEDIUM = suspicious, investigate before killing" -ForegroundColor Yellow
    Write-Host "    LOW    = wasteful but harmless" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Kill confirmations are CASE-SENSITIVE: YES, KILL ALL" -ForegroundColor DarkGray
    Write-Host "  Use [12] to adjust idle hours and memory thresholds." -ForegroundColor DarkGray
    Write-Host ""
}

function Run-FullScan {
    param([int]$IdleHours = 24, [int]$HiddenMemMB = 50)
    Write-Host "`n  ══ RUNNING FULL ZOMBIE SCAN ══" -ForegroundColor Yellow
    $all = @()
    $all += @(Detect-NotResponding)
    $all += @(Detect-Orphaned)
    $all += @(Detect-IdleLongRunning -HoursThreshold $IdleHours)
    $all += @(Detect-HiddenResourceHogs -MemThresholdMB $HiddenMemMB)
    $all += @(Detect-SuspendedThreads)
    $all += @(Detect-GhostServices)
    $all += @(Detect-DuplicateProcesses)
    return $all
}

function Display-Results {
    param($Data)
    if (!$Data -or $Data.Count -eq 0) {
        Write-Host "`n  ✓ No zombie processes detected! System looks clean." -ForegroundColor Green
        return
    }
    Write-Host "`n  Found $($Data.Count) zombie-like processes:`n" -ForegroundColor Red

    $grouped = $Data | Group-Object Type
    foreach ($g in $grouped) {
        $color = switch ($g.Name) {
            "NOT_RESPONDING"  { "Red" }
            "ORPHANED"        { "Yellow" }
            "IDLE_LONGRUN"    { "DarkYellow" }
            "HIDDEN_HOG"      { "Magenta" }
            "ALL_SUSPENDED"   { "DarkMagenta" }
            "GHOST_SERVICE"   { "DarkCyan" }
            "EXCESSIVE_DUPES" { "DarkRed" }
            default           { "White" }
        }
        Write-Host "  ── $($g.Name) ($($g.Count) found) ──" -ForegroundColor $color
        $g.Group | Format-Table -Property @(
            @{L="Severity";E={$_.Severity};W=10},
            @{L="Name";E={$_.Name};W=25},
            @{L="PID";E={$_.PID};W=8},
            @{L="Mem MB";E={$_.Mem_MB};W=10},
            @{L="Started";E={$_.StartTime};W=18},
            @{L="Detail";E={$_.Detail}}
        ) -AutoSize -Wrap
    }

    $totalMem = [math]::Round(($Data | Measure-Object Mem_MB -Sum).Sum, 1)
    $highCount = ($Data | Where-Object { $_.Severity -eq "HIGH" }).Count
    Write-Host "  ┌─────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  Total zombies: $($Data.Count)  |  HIGH severity: $highCount  |  Memory wasted: $totalMem MB" -ForegroundColor White
    Write-Host "  └─────────────────────────────────────────────┘" -ForegroundColor DarkGray
}

function Kill-Interactive {
    param($Data)
    if (!$Data -or $Data.Count -eq 0) { Write-Host "  No zombies to kill." -ForegroundColor DarkGray; return }

    Write-Host "`n  ── INTERACTIVE ZOMBIE KILLER ──" -ForegroundColor Red
    $i = 1
    foreach ($z in $Data) {
        $sev = switch ($z.Severity) { "HIGH" { "Red" }; "MEDIUM" { "Yellow" }; default { "DarkGray" } }
        Write-Host ("  [{0,2}] [{1,-6}] {2,-25} PID={3,-7} Mem={4}MB — {5}" -f $i, $z.Severity, $z.Name, $z.PID, $z.Mem_MB, $z.Detail) -ForegroundColor $sev
        $i++
    }

    Write-Host "`n  Enter numbers to kill (comma-separated), 'all' for all safe ones, or 'none' to cancel" -ForegroundColor DarkGray
    $input_val = Read-Host "  Selection"

    if ($input_val -eq "none") { return }

    $toKill = @()
    if ($input_val -eq "all") {
        $toKill = $Data | Where-Object { $_.Safe }
    } else {
        $indices = $input_val -split "," | ForEach-Object { [int]$_.Trim() - 1 }
        foreach ($idx in $indices) {
            if ($idx -ge 0 -and $idx -lt $Data.Count) { $toKill += $Data[$idx] }
        }
    }

    if ($toKill.Count -eq 0) { Write-Host "  Nothing selected." -ForegroundColor DarkGray; return }

    Write-Host "`n  About to kill $($toKill.Count) processes:" -ForegroundColor Red
    $toKill | ForEach-Object { Write-Host "    - $($_.Name) (PID $($_.PID))" -ForegroundColor Yellow }
    $confirm = Read-Host "`n  Type 'YES' to confirm"
    if ($confirm -ne "YES") { Write-Host "  Cancelled." -ForegroundColor DarkGray; return }

    foreach ($z in $toKill) {
        try {
            Stop-Process -Id $z.PID -Force -ErrorAction Stop
            Write-Host "  ✓ Killed $($z.Name) (PID $($z.PID))" -ForegroundColor Green
        } catch {
            Write-Host "  ✗ Failed: $($z.Name) — $_" -ForegroundColor Red
        }
    }
}

function Kill-AllSafe {
    param($Data)
    $safe = $Data | Where-Object { $_.Safe }
    if (!$safe -or $safe.Count -eq 0) { Write-Host "  No safe-to-kill zombies found." -ForegroundColor DarkGray; return }

    Write-Host "`n  BATCH KILL — $($safe.Count) safe zombies:" -ForegroundColor Red
    $safe | ForEach-Object { Write-Host "    $($_.Name) (PID $($_.PID)) — $($_.Mem_MB) MB" -ForegroundColor Yellow }
    $totalMem = [math]::Round(($safe | Measure-Object Mem_MB -Sum).Sum, 1)
    Write-Host "  Potential memory recovery: $totalMem MB" -ForegroundColor Cyan

    $confirm = Read-Host "`n  Type 'KILL ALL' to proceed"
    if ($confirm -ne "KILL ALL") { Write-Host "  Cancelled." -ForegroundColor DarkGray; return }

    $killed = 0; $failed = 0
    foreach ($z in $safe) {
        try {
            Stop-Process -Id $z.PID -Force -ErrorAction Stop
            Write-Host "  ✓ $($z.Name)" -ForegroundColor Green
            $killed++
        } catch { Write-Host "  ✗ $($z.Name): $_" -ForegroundColor Red; $failed++ }
    }
    Write-Host "`n  Done: $killed killed, $failed failed." -ForegroundColor Cyan
}

function Export-ZombieReport {
    param($Data)
    if (!$Data -or $Data.Count -eq 0) { Write-Host "  No data to export." -ForegroundColor DarkGray; return }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = "$ExportDir\ZombieReport_$timestamp.csv"
    $htmlPath = "$ExportDir\ZombieReport_$timestamp.html"

    $Data | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "  Exported CSV: $csvPath" -ForegroundColor Green

    $totalMem = [math]::Round(($Data | Measure-Object Mem_MB -Sum).Sum, 1)
    $html = @"
<html><head><style>
body { font-family: Consolas, monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
h1 { color: #e94560; } h2 { color: #0f3460; background: #e94560; padding: 8px; display: inline-block; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th { background: #16213e; color: #e94560; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #0f3460; }
tr:hover { background: #16213e; }
.HIGH { color: #e94560; font-weight: bold; } .MEDIUM { color: #f5a623; } .LOW { color: #a8d8ea; }
.summary { background: #16213e; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #e94560; }
</style></head><body>
<h1>🧟 Zombie Process Report</h1>
<div class="summary">
<p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Zombies Found: $($Data.Count) | Memory Wasted: ${totalMem} MB</p>
</div>
<table><tr><th>Type</th><th>Severity</th><th>Name</th><th>PID</th><th>Mem MB</th><th>Started</th><th>Detail</th><th>Safe to Kill</th></tr>
"@
    foreach ($row in ($Data | Sort-Object Severity)) {
        $safeText = if ($row.Safe) { "✓ Yes" } else { "⚠ Caution" }
        $html += "<tr><td>$($row.Type)</td><td class='$($row.Severity)'>$($row.Severity)</td><td>$($row.Name)</td><td>$($row.PID)</td><td>$($row.Mem_MB)</td><td>$($row.StartTime)</td><td>$($row.Detail)</td><td>$safeText</td></tr>"
    }
    $html += "</table></body></html>"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "  Exported HTML: $htmlPath" -ForegroundColor Green

    $open = Read-Host "  Open HTML report? (y/N)"
    if ($open -eq "y") { Start-Process $htmlPath }
}

# ── Main Loop ──
$IdleHoursThreshold = 24
$HiddenMemThreshold = 50
$zombieData = $null

# ── Auto-Export Mode (for scheduled tasks) ──
if ($AutoExport) {
    Write-Host "  [AUTO] Running unattended zombie scan..." -ForegroundColor DarkGray
    $zombieData = Run-FullScan -IdleHours $IdleHoursThreshold -HiddenMemMB $HiddenMemThreshold
    if ($zombieData -and $zombieData.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvPath = "$ExportDir\ZombieReport_Auto_$timestamp.csv"
        $htmlPath = "$ExportDir\ZombieReport_Auto_$timestamp.html"
        $zombieData | Export-Csv -Path $csvPath -NoTypeInformation
        $totalMem = [math]::Round(($zombieData | Measure-Object Mem_MB -Sum).Sum, 1)
        $html = @"
<html><head><style>
body { font-family: Consolas, monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
h1 { color: #e94560; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th { background: #16213e; color: #e94560; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #0f3460; }
.HIGH { color: #e94560; font-weight: bold; } .MEDIUM { color: #f5a623; } .LOW { color: #a8d8ea; }
</style></head><body>
<h1>Zombie Process Report (Automated)</h1>
<p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Zombies: $($zombieData.Count) | Memory Wasted: ${totalMem} MB</p>
<table><tr><th>Type</th><th>Severity</th><th>Name</th><th>PID</th><th>Mem MB</th><th>Detail</th></tr>
"@
        foreach ($row in $zombieData) {
            $html += "<tr><td>$($row.Type)</td><td class='$($row.Severity)'>$($row.Severity)</td><td>$($row.Name)</td><td>$($row.PID)</td><td>$($row.Mem_MB)</td><td>$($row.Detail)</td></tr>"
        }
        $html += "</table></body></html>"
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host "  [AUTO] Exported: $csvPath" -ForegroundColor Green
        Write-Host "  [AUTO] Exported: $htmlPath" -ForegroundColor Green
    } else {
        Write-Host "  [AUTO] No zombies detected. System clean." -ForegroundColor Green
    }
    exit
}

Show-Banner
Write-Host "  Ready. Run [1] for a full scan, or [?] for help.`n" -ForegroundColor DarkGray

while ($true) {
    Show-Menu
    $choice = Read-Host "  Select option"
    while ($true) {
        switch ($choice) {
            "1"  {
                $zombieData = Run-FullScan -IdleHours $IdleHoursThreshold -HiddenMemMB $HiddenMemThreshold
                Display-Results $zombieData
            }
            "2"  { $r = @(Detect-NotResponding); Display-Results $r }
            "3"  { $r = @(Detect-Orphaned); Display-Results $r }
            "4"  {
                $h = Read-Host "  Hours threshold (default=$IdleHoursThreshold, Enter to keep)"
                if ($h) { $IdleHoursThreshold = [int]$h }
                $r = @(Detect-IdleLongRunning -HoursThreshold $IdleHoursThreshold); Display-Results $r
            }
            "5"  {
                $m = Read-Host "  Memory threshold in MB (default=$HiddenMemThreshold, Enter to keep)"
                if ($m) { $HiddenMemThreshold = [int]$m }
                $r = @(Detect-HiddenResourceHogs -MemThresholdMB $HiddenMemThreshold); Display-Results $r
            }
            "6"  { $r = @(Detect-SuspendedThreads); Display-Results $r }
            "7"  { $r = @(Detect-GhostServices); Display-Results $r }
            "8"  { $r = @(Detect-DuplicateProcesses); Display-Results $r }
            "9"  {
                if (!$zombieData) {
                    Write-Host "  No scan data yet. Running full scan first..." -ForegroundColor DarkYellow
                    $zombieData = Run-FullScan -IdleHours $IdleHoursThreshold -HiddenMemMB $HiddenMemThreshold
                    Display-Results $zombieData
                }
                Kill-Interactive $zombieData
            }
            "10" {
                if (!$zombieData) {
                    Write-Host "  No scan data yet. Running full scan first..." -ForegroundColor DarkYellow
                    $zombieData = Run-FullScan -IdleHours $IdleHoursThreshold -HiddenMemMB $HiddenMemThreshold
                    Display-Results $zombieData
                }
                Kill-AllSafe $zombieData
            }
            "11" {
                if (!$zombieData) {
                    Write-Host "  No scan data yet. Running full scan first..." -ForegroundColor DarkYellow
                    $zombieData = Run-FullScan -IdleHours $IdleHoursThreshold -HiddenMemMB $HiddenMemThreshold
                }
                Export-ZombieReport $zombieData
            }
            "12" {
                Write-Host "`n  ── CONFIGURE THRESHOLDS ──" -ForegroundColor Yellow
                Write-Host "  Current: Idle=$IdleHoursThreshold hours, Hidden Memory=$HiddenMemThreshold MB" -ForegroundColor DarkGray
                $h = Read-Host "  Idle hours threshold (Enter to keep current)"
                if ($h) { $IdleHoursThreshold = [int]$h; Write-Host "  → Set to $IdleHoursThreshold hours" -ForegroundColor Green }
                $m = Read-Host "  Hidden process memory threshold in MB (Enter to keep current)"
                if ($m) { $HiddenMemThreshold = [int]$m; Write-Host "  → Set to $HiddenMemThreshold MB" -ForegroundColor Green }
            }
            "?"  { Show-Help }
            "0"  { Write-Host "`n  Goodbye!`n" -ForegroundColor Red; exit }
            default { Write-Host "  Invalid option. Type [?] for help." -ForegroundColor Red }
        }
        Write-Host ""
        Write-Host "  Press Enter for menu, or type next option directly:" -ForegroundColor DarkGray -NoNewline
        $next = Read-Host " "
        if ($next) {
            $choice = $next
            Show-Banner $zombieData -NoClear
        } else { break }
    }
    Show-Banner $zombieData
}

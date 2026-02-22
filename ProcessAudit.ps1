#Requires -Version 5.1
<#
.SYNOPSIS
    Advanced Windows Process Auditor — Segment, categorize, and analyze all running processes.
.DESCRIPTION
    Provides an interactive menu to audit processes by usage, relevance, impact, and runtime.
    Supports filtering, sorting, exporting, and selective process termination.
.NOTES
    Run as Administrator for full visibility into all system processes.
#>

# ── Config ──
$ExportDir = "$env:USERPROFILE\Desktop\ProcessAudit"
if (!(Test-Path $ExportDir)) { New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null }

# ── Category Definitions (user can edit this hashtable to customize) ──
$CategoryMap = [ordered]@{
    # System Critical — never kill these
    "csrss"           = @{ Category = "System/Critical";    Killable = $false }
    "smss"            = @{ Category = "System/Critical";    Killable = $false }
    "wininit"         = @{ Category = "System/Critical";    Killable = $false }
    "winlogon"        = @{ Category = "System/Critical";    Killable = $false }
    "lsass"           = @{ Category = "System/Security";    Killable = $false }
    "services"        = @{ Category = "System/Critical";    Killable = $false }
    "System"          = @{ Category = "System/Kernel";      Killable = $false }
    "Idle"            = @{ Category = "System/Kernel";      Killable = $false }
    "Registry"        = @{ Category = "System/Kernel";      Killable = $false }
    "Memory Compression" = @{ Category = "System/Kernel";   Killable = $false }
    "svchost"         = @{ Category = "System/ServiceHost"; Killable = $false }
    "fontdrvhost"     = @{ Category = "System/Display";     Killable = $false }
    "dwm"             = @{ Category = "Shell/Compositor";   Killable = $false }
    "conhost"         = @{ Category = "System/Console";     Killable = $false }

    # Shell & UI
    "explorer"        = @{ Category = "Shell/UI";           Killable = $true }
    "ShellExperienceHost" = @{ Category = "Shell/UI";       Killable = $true }
    "StartMenuExperienceHost" = @{ Category = "Shell/UI";   Killable = $true }
    "SearchHost"      = @{ Category = "Search/Indexing";    Killable = $true }
    "SearchIndexer"   = @{ Category = "Search/Indexing";    Killable = $true }
    "SearchProtocolHost" = @{ Category = "Search/Indexing"; Killable = $true }
    "Widgets"         = @{ Category = "Shell/Widgets";      Killable = $true }
    "WidgetService"   = @{ Category = "Shell/Widgets";      Killable = $true }

    # Security
    "MsMpEng"         = @{ Category = "Security/Defender";  Killable = $false }
    "NisSrv"          = @{ Category = "Security/Defender";  Killable = $false }
    "SecurityHealthService" = @{ Category = "Security/Defender"; Killable = $false }

    # Microsoft Bloat
    "OneDrive"        = @{ Category = "Cloud/OneDrive";     Killable = $true }
    "Teams"           = @{ Category = "Communication/Teams"; Killable = $true }
    "PhoneExperienceHost" = @{ Category = "Bloat/PhoneLink"; Killable = $true }
    "YourPhone"       = @{ Category = "Bloat/PhoneLink";    Killable = $true }
    "GameBar*"        = @{ Category = "Bloat/GameBar";      Killable = $true }
    "gameinputsvc"    = @{ Category = "Bloat/GameBar";      Killable = $true }
    "Cortana"         = @{ Category = "Bloat/Cortana";      Killable = $true }
    "Microsoft.Photos" = @{ Category = "App/Photos";        Killable = $true }
    "Video.UI"        = @{ Category = "App/Movies";         Killable = $true }
    "HxOutlook"       = @{ Category = "App/Mail";           Killable = $true }
    "HxCalendarAppImm" = @{ Category = "App/Calendar";     Killable = $true }
    "SkypeApp"        = @{ Category = "Bloat/Skype";        Killable = $true }
    "Copilot"         = @{ Category = "Bloat/AI";           Killable = $true }

    # Browsers
    "chrome"          = @{ Category = "Browser/Chrome";     Killable = $true }
    "msedge"          = @{ Category = "Browser/Edge";       Killable = $true }
    "firefox"         = @{ Category = "Browser/Firefox";    Killable = $true }
    "brave"           = @{ Category = "Browser/Brave";      Killable = $true }
    "opera"           = @{ Category = "Browser/Opera";      Killable = $true }

    # Development
    "Code"            = @{ Category = "Dev/VSCode";         Killable = $true }
    "devenv"          = @{ Category = "Dev/VisualStudio";   Killable = $true }
    "idea64"          = @{ Category = "Dev/IntelliJ";       Killable = $true }
    "node"            = @{ Category = "Dev/Node.js";        Killable = $true }
    "python"          = @{ Category = "Dev/Python";         Killable = $true }
    "java"            = @{ Category = "Dev/Java";           Killable = $true }
    "WindowsTerminal" = @{ Category = "Dev/Terminal";       Killable = $true }
    "powershell"      = @{ Category = "Dev/PowerShell";     Killable = $true }
    "pwsh"            = @{ Category = "Dev/PowerShell";     Killable = $true }
    "cmd"             = @{ Category = "Dev/CommandPrompt";  Killable = $true }
    "git"             = @{ Category = "Dev/Git";            Killable = $true }
    "docker"          = @{ Category = "Dev/Docker";         Killable = $true }
    "Docker Desktop"  = @{ Category = "Dev/Docker";         Killable = $true }

    # Communication
    "Slack"           = @{ Category = "Communication/Slack"; Killable = $true }
    "Discord"         = @{ Category = "Communication/Discord"; Killable = $true }
    "Zoom"            = @{ Category = "Communication/Zoom"; Killable = $true }
    "Spotify"         = @{ Category = "Media/Spotify";      Killable = $true }

    # GPU / Hardware
    "nvcontainer"     = @{ Category = "Hardware/NVIDIA";    Killable = $true }
    "NVIDIA*"         = @{ Category = "Hardware/NVIDIA";    Killable = $true }
    "RadeonSoftware"  = @{ Category = "Hardware/AMD";       Killable = $true }
    "RtkAudUService64" = @{ Category = "Hardware/Audio";   Killable = $false }
}

# ── Functions ──

function Get-ProcessCategory {
    param([string]$ProcessName)
    foreach ($key in $CategoryMap.Keys) {
        if ($ProcessName -like $key -or $ProcessName -eq $key) {
            return $CategoryMap[$key]
        }
    }
    return @{ Category = "Uncategorized"; Killable = $true }
}

function Get-ImpactLevel {
    param([double]$MemMB, [double]$CpuSec)
    if ($MemMB -gt 1000 -or $CpuSec -gt 600) { return "CRITICAL" }
    if ($MemMB -gt 500 -or $CpuSec -gt 300)  { return "HIGH" }
    if ($MemMB -gt 100 -or $CpuSec -gt 60)   { return "MEDIUM" }
    if ($MemMB -gt 20)                         { return "LOW" }
    return "MINIMAL"
}

function Get-RelevanceScore {
    param([string]$Category, [bool]$Responding, [double]$CpuSec, [double]$MemMB)
    # Relevance: how important is this process to the user's current session?
    # ESSENTIAL = system will break without it
    # ACTIVE    = user is actively using it (has CPU activity)
    # PASSIVE   = running but not actively used
    # BLOAT     = likely unnecessary
    # UNKNOWN   = can't determine, needs user review
    if ($Category -match "^System/" -or $Category -match "^Security/") { return "ESSENTIAL" }
    if ($Category -match "^Shell/") { return "ESSENTIAL" }
    if ($Category -match "^Bloat/") { return "BLOAT" }
    if (!$Responding) { return "BLOAT" }
    if ($CpuSec -gt 5) { return "ACTIVE" }
    if ($Category -eq "Uncategorized") { return "UNKNOWN" }
    return "PASSIVE"
}

function Collect-ProcessData {
    Write-Host "`n  Scanning all processes..." -ForegroundColor DarkGray
    $allProcs = Get-Process -ErrorAction SilentlyContinue
    $cimProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $cimMap = @{}
    foreach ($c in $cimProcs) { $cimMap[$c.ProcessId] = $c }

    $results = foreach ($proc in $allProcs) {
        $cpu = try { $proc.CPU } catch { 0 }
        if ($null -eq $cpu) { $cpu = 0 }
        $startTime = try { $proc.StartTime } catch { $null }
        $runtime = if ($startTime) { (Get-Date) - $startTime } else { $null }
        $catInfo = Get-ProcessCategory $proc.ProcessName
        $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
        $cimInfo = $cimMap[$proc.Id]
        $cmdLine = if ($cimInfo) { $cimInfo.CommandLine } else { "" }
        $parentPid = if ($cimInfo) { $cimInfo.ParentProcessId } else { $null }
        $owner = try { ($cimInfo | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue).User } catch { "N/A" }
        $responding = try { $proc.Responding } catch { $true }
        $threadCount = try { $proc.Threads.Count } catch { 0 }
        $handleCount = try { $proc.HandleCount } catch { 0 }

        $cpuRounded = [math]::Round($cpu, 1)
        $relevance = Get-RelevanceScore $catInfo.Category $responding $cpuRounded $memMB

        [PSCustomObject]@{
            Name         = $proc.ProcessName
            PID          = $proc.Id
            ParentPID    = $parentPid
            Category     = $catInfo.Category
            Killable     = $catInfo.Killable
            Relevance    = $relevance
            "Mem_MB"     = $memMB
            "CPU_Sec"    = $cpuRounded
            Impact       = Get-ImpactLevel $memMB $cpu
            Responding   = $responding
            Threads      = $threadCount
            Handles      = $handleCount
            Owner        = if ($owner) { $owner } else { "N/A" }
            StartTime    = if ($startTime) { $startTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
            RuntimeDays  = if ($runtime) { [math]::Round($runtime.TotalDays, 2) } else { 0 }
            RuntimeStr   = if ($runtime) { "{0}d {1}h {2}m" -f $runtime.Days, $runtime.Hours, $runtime.Minutes } else { "N/A" }
            CommandLine  = if ($cmdLine) { $cmdLine.Substring(0, [Math]::Min(120, $cmdLine.Length)) } else { "" }
        }
    }
    return $results | Sort-Object Mem_MB -Descending
}

function Show-HealthSummary {
    param($Data)
    if (!$Data) { return }
    $totalMem = [math]::Round(($Data | Measure-Object Mem_MB -Sum).Sum, 1)
    $totalProcs = $Data.Count
    $critCount = ($Data | Where-Object { $_.Impact -in @("CRITICAL","HIGH") }).Count
    $bloatCount = ($Data | Where-Object { $_.Relevance -eq "BLOAT" }).Count
    $bloatMem = [math]::Round(($Data | Where-Object { $_.Relevance -eq "BLOAT" } | Measure-Object Mem_MB -Sum).Sum, 1)
    $uncatCount = ($Data | Where-Object { $_.Category -eq "Uncategorized" }).Count
    $notResp = ($Data | Where-Object { $_.Responding -eq $false }).Count

    Write-Host "  ┌─ SYSTEM HEALTH AT A GLANCE ─────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host ("  │  Processes: {0,-6}  Total Memory: {1,-10} MB          │" -f $totalProcs, $totalMem) -ForegroundColor White
    $hColor = if ($critCount -gt 5) { "Red" } elseif ($critCount -gt 0) { "Yellow" } else { "Green" }
    Write-Host ("  │  High Impact: {0,-4}  Bloat: {1} procs ({2} MB)  Not Responding: {3,-3}│" -f $critCount, $bloatCount, $bloatMem, $notResp) -ForegroundColor $hColor
    if ($uncatCount -gt 0) {
        Write-Host ("  │  ⚠ {0} uncategorized processes — review with option [6]     │" -f $uncatCount) -ForegroundColor Yellow
    }
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""
}

function Show-Banner {
    param($Data, [switch]$NoClear)
    if (!$NoClear) { Clear-Host }
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║         WINDOWS PROCESS AUDITOR v3.0                    ║" -ForegroundColor Cyan
    Write-Host "  ║   Segment · Categorize · Analyze · Control             ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Show-HealthSummary $Data
}

function Show-Menu {
    Write-Host "  ── ANALYZE ──────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "   [1]  Full Report         — all processes, sortable     " -ForegroundColor White
    Write-Host "   [2]  By Category         — grouped with totals         " -ForegroundColor White
    Write-Host "   [3]  Top Resource Hogs   — biggest CPU & memory users  " -ForegroundColor White
    Write-Host "   [4]  Impact Analysis     — CRITICAL & HIGH only        " -ForegroundColor White
    Write-Host "   [5]  Long-Running        — processes running > N hours " -ForegroundColor White
    Write-Host "   [6]  Uncategorized       — unknown processes to review " -ForegroundColor White
    Write-Host "   [7]  Search              — find by name/keyword        " -ForegroundColor White
    Write-Host "   [15] Relevance           — Essential → Bloat breakdown " -ForegroundColor White
    Write-Host ""
    Write-Host "  ── DEEP DIVE ────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "   [11] Network Activity    — who's using the network     " -ForegroundColor White
    Write-Host "   [12] Disk I/O            — who's hammering the disk    " -ForegroundColor White
    Write-Host "   [13] Process Tree        — parent → child view         " -ForegroundColor White
    Write-Host "   [14] Startup Programs    — what auto-starts on boot    " -ForegroundColor White
    Write-Host ""
    Write-Host "  ── TAKE ACTION ──────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "   [8]  Kill Process        — kill by PID or name         " -ForegroundColor White
    Write-Host "   [9]  Kill by Category    — batch kill a whole group    " -ForegroundColor White
    Write-Host "   [10] Export Report       — save CSV + HTML to Desktop  " -ForegroundColor White
    Write-Host "   [16] Restore Point       — create safety snapshot      " -ForegroundColor White
    Write-Host ""
    Write-Host "  ── OTHER ────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "   [17] Refresh Data   [?] Help   [0] Exit               " -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Help {
    Write-Host "`n  ── QUICK HELP ──" -ForegroundColor Cyan
    Write-Host "  This tool scans every running process and gives you full control." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Workflow for first-time users:" -ForegroundColor White
    Write-Host "    1. Check the health summary above — note Bloat count and High Impact" -ForegroundColor DarkGray
    Write-Host "    2. Run [15] Relevance — see what's ESSENTIAL vs BLOAT" -ForegroundColor DarkGray
    Write-Host "    3. Run [6] Uncategorized — investigate unknown processes" -ForegroundColor DarkGray
    Write-Host "    4. Run [16] Restore Point — create a safety snapshot" -ForegroundColor DarkGray
    Write-Host "    5. Run [9] Kill by Category — remove bloat categories" -ForegroundColor DarkGray
    Write-Host "    6. Run [10] Export — save a clean baseline report" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Color guide:" -ForegroundColor White
    Write-Host "    Green  = safe / killable / low impact" -ForegroundColor Green
    Write-Host "    Yellow = caution / medium impact" -ForegroundColor Yellow
    Write-Host "    Red    = protected / high impact / danger" -ForegroundColor Red
    Write-Host "    Cyan   = informational" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Kill confirmations are CASE-SENSITIVE: type YES, FORCE, or KILL ALL exactly." -ForegroundColor DarkGray
    Write-Host ""
}

function Display-Table {
    param($Data, [int]$Top = 0)
    $set = if ($Top -gt 0) { $Data | Select-Object -First $Top } else { $Data }
    $set | Format-Table -Property Name, PID, Category, Relevance, Mem_MB, CPU_Sec, Impact, Responding, RuntimeStr, Owner -AutoSize
    Write-Host "  Showing $($set.Count) of $($Data.Count) processes" -ForegroundColor DarkGray
}

function Option-FullReport {
    param($Data)
    Write-Host "`n  ── FULL PROCESS REPORT ──" -ForegroundColor Yellow
    Write-Host "  Sort by: [1] Memory  [2] CPU  [3] Runtime  [4] Name  [5] Category" -ForegroundColor DarkGray
    $sortChoice = Read-Host "  Choice (default=1)"
    $sorted = switch ($sortChoice) {
        "2" { $Data | Sort-Object CPU_Sec -Descending }
        "3" { $Data | Sort-Object RuntimeDays -Descending }
        "4" { $Data | Sort-Object Name }
        "5" { $Data | Sort-Object Category, Name }
        default { $Data | Sort-Object Mem_MB -Descending }
    }
    $showAll = Read-Host "  Show all? (y/N, default shows top 50)"
    if ($showAll -eq "y") { Display-Table $sorted } else { Display-Table $sorted -Top 50 }
}

function Option-ByCategory {
    param($Data)
    Write-Host "`n  ── CATEGORY BREAKDOWN ──" -ForegroundColor Yellow
    $groups = $Data | Group-Object Category | Sort-Object @{E={($_.Group | Measure-Object Mem_MB -Sum).Sum}; Desc=$true}
    foreach ($g in $groups) {
        $totalMem = [math]::Round(($g.Group | Measure-Object Mem_MB -Sum).Sum, 1)
        $totalCpu = [math]::Round(($g.Group | Measure-Object CPU_Sec -Sum).Sum, 1)
        $count = $g.Count
        $killable = if ($g.Group[0].Killable) { "[KILLABLE]" } else { "[PROTECTED]" }
        $color = if ($g.Group[0].Killable) { "Green" } else { "Red" }
        Write-Host ("  {0,-30} {1,3} procs | {2,8} MB | {3,8}s CPU  {4}" -f $g.Name, $count, $totalMem, $totalCpu, $killable) -ForegroundColor $color
    }
    Write-Host ""
    $expand = Read-Host "  Expand a category? (type name or Enter to skip)"
    if ($expand) {
        $match = $Data | Where-Object { $_.Category -like "*$expand*" }
        if ($match) { Display-Table $match } else { Write-Host "  No match found." -ForegroundColor Red }
    }
}

function Option-TopHogs {
    param($Data)
    Write-Host "`n  ── TOP RESOURCE HOGS ──" -ForegroundColor Yellow
    $n = Read-Host "  How many to show? (default=20)"
    if (!$n) { $n = 20 }
    Write-Host "`n  Top $n by MEMORY:" -ForegroundColor Magenta
    $Data | Sort-Object Mem_MB -Descending | Select-Object -First $n |
        Format-Table Name, PID, Category, Mem_MB, Impact, Killable -AutoSize
    Write-Host "  Top $n by CPU:" -ForegroundColor Magenta
    $Data | Sort-Object CPU_Sec -Descending | Select-Object -First $n |
        Format-Table Name, PID, Category, CPU_Sec, Impact, Killable -AutoSize
}

function Option-ImpactAnalysis {
    param($Data)
    Write-Host "`n  ── HIGH IMPACT PROCESSES ──" -ForegroundColor Yellow
    $critical = $Data | Where-Object { $_.Impact -in @("CRITICAL", "HIGH") }
    if ($critical) {
        Display-Table $critical
        Write-Host "`n  Total high-impact memory: $([math]::Round(($critical | Measure-Object Mem_MB -Sum).Sum, 1)) MB" -ForegroundColor Red
    } else {
        Write-Host "  No CRITICAL or HIGH impact processes found." -ForegroundColor Green
    }
}

function Option-LongRunning {
    param($Data)
    Write-Host "`n  ── LONG-RUNNING PROCESSES ──" -ForegroundColor Yellow
    $threshold = Read-Host "  Minimum hours running? (default=24)"
    if (!$threshold) { $threshold = 24 }
    $long = $Data | Where-Object { $_.RuntimeDays -gt ($threshold / 24) } | Sort-Object RuntimeDays -Descending
    if ($long) { Display-Table $long } else { Write-Host "  No processes running longer than $threshold hours." -ForegroundColor Green }
}

function Option-Uncategorized {
    param($Data)
    Write-Host "`n  ── UNCATEGORIZED PROCESSES ──" -ForegroundColor Yellow
    Write-Host "  These are processes not in the known category map. Review them for bloat." -ForegroundColor DarkGray
    $unknown = $Data | Where-Object { $_.Category -eq "Uncategorized" } | Sort-Object Mem_MB -Descending
    if ($unknown) { Display-Table $unknown } else { Write-Host "  All processes are categorized!" -ForegroundColor Green }
}

function Option-Search {
    param($Data)
    $term = Read-Host "`n  Search term (name, category, or command line)"
    $results = $Data | Where-Object {
        $_.Name -like "*$term*" -or $_.Category -like "*$term*" -or $_.CommandLine -like "*$term*"
    }
    if ($results) {
        Display-Table $results
        $results | ForEach-Object {
            Write-Host ("    PID {0}: {1}" -f $_.PID, $_.CommandLine) -ForegroundColor DarkGray
        }
    } else { Write-Host "  No matches for '$term'." -ForegroundColor Red }
}

function Option-KillProcess {
    param($Data)
    $target = Read-Host "`n  Enter PID or process name to kill"
    $matchedProcs = $Data | Where-Object { $_.PID -eq $target -or $_.Name -like "*$target*" }
    if (!$matchedProcs) { Write-Host "  No process found." -ForegroundColor Red; return }

    foreach ($p in $matchedProcs) {
        $color = if ($p.Killable) { "Yellow" } else { "Red" }
        $safety = if ($p.Killable) { "SAFE TO KILL" } else { "!! PROTECTED — KILLING MAY CRASH SYSTEM !!" }
        Write-Host ("  [{0}] PID={1}  {2}  Mem={3}MB  Category={4}" -f $safety, $p.PID, $p.Name, $p.Mem_MB, $p.Category) -ForegroundColor $color
    }

    $confirm = Read-Host "`n  Proceed with kill? Type 'YES' to confirm"
    if ($confirm -eq "YES") {
        foreach ($p in $matchedProcs) {
            if (!$p.Killable) {
                $force = Read-Host "  $($p.Name) (PID $($p.PID)) is PROTECTED. Force kill anyway? (type 'FORCE')"
                if ($force -ne "FORCE") { Write-Host "  Skipped $($p.Name)." -ForegroundColor DarkGray; continue }
            }
            try {
                Stop-Process -Id $p.PID -Force -ErrorAction Stop
                Write-Host "  Killed $($p.Name) (PID $($p.PID))" -ForegroundColor Green
            } catch {
                Write-Host "  Failed to kill $($p.Name): $_" -ForegroundColor Red
            }
        }
    } else { Write-Host "  Cancelled." -ForegroundColor DarkGray }
}

function Option-KillByCategory {
    param($Data)
    Write-Host "`n  ── KILLABLE CATEGORIES ──" -ForegroundColor Yellow
    $killableGroups = $Data | Where-Object { $_.Killable } | Group-Object Category | Sort-Object Name
    $i = 1
    $catList = @()
    foreach ($g in $killableGroups) {
        $totalMem = [math]::Round(($g.Group | Measure-Object Mem_MB -Sum).Sum, 1)
        Write-Host ("  [{0,2}] {1,-30} {2,3} procs | {3,8} MB" -f $i, $g.Name, $g.Count, $totalMem) -ForegroundColor White
        $catList += $g.Name
        $i++
    }
    $pick = Read-Host "`n  Enter number(s) to kill (comma-separated, e.g. 1,3,5)"
    if (!$pick) { return }
    $indices = $pick -split "," | ForEach-Object { [int]$_.Trim() - 1 }
    $toKill = @()
    foreach ($idx in $indices) {
        if ($idx -ge 0 -and $idx -lt $catList.Count) { $toKill += $catList[$idx] }
    }
    $victims = $Data | Where-Object { $_.Category -in $toKill -and $_.Killable }
    Write-Host "`n  Will kill $($victims.Count) processes in: $($toKill -join ', ')" -ForegroundColor Red
    $victims | Format-Table Name, PID, Category, Mem_MB -AutoSize
    $confirm = Read-Host "  Type 'YES' to confirm batch kill"
    if ($confirm -eq "YES") {
        foreach ($v in $victims) {
            try {
                Stop-Process -Id $v.PID -Force -ErrorAction Stop
                Write-Host "  Killed $($v.Name) (PID $($v.PID))" -ForegroundColor Green
            } catch {
                Write-Host "  Failed: $($v.Name) — $_" -ForegroundColor Red
            }
        }
    } else { Write-Host "  Cancelled." -ForegroundColor DarkGray }
}

function Option-Export {
    param($Data)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = "$ExportDir\ProcessAudit_$timestamp.csv"
    $htmlPath = "$ExportDir\ProcessAudit_$timestamp.html"

    # CSV
    $Data | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "  Exported CSV: $csvPath" -ForegroundColor Green

    # HTML
    $totalMem = [math]::Round(($Data | Measure-Object Mem_MB -Sum).Sum, 1)
    $htmlHead = @"
<html><head><style>
body { font-family: Consolas, monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
h1 { color: #569cd6; } h2 { color: #4ec9b0; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th { background: #264f78; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #333; }
tr:hover { background: #2a2d2e; }
.critical { color: #f44747; font-weight: bold; } .high { color: #ce9178; }
.medium { color: #dcdcaa; } .low { color: #6a9955; } .minimal { color: #608b4e; }
.protected { color: #f44747; } .killable { color: #6a9955; }
.essential { color: #569cd6; } .active { color: #4ec9b0; } .passive { color: #dcdcaa; }
.bloat { color: #f44747; } .unknown { color: #ce9178; }
.summary { background: #252526; padding: 15px; border-radius: 8px; margin: 10px 0; }
</style></head><body>
<h1>Process Audit Report</h1>
<p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Total Processes: $($Data.Count) | Total Memory: ${totalMem} MB</p>
"@
    $htmlBody = "<table><tr><th>Name</th><th>PID</th><th>Category</th><th>Relevance</th><th>Mem MB</th><th>CPU Sec</th><th>Impact</th><th>Killable</th><th>Runtime</th><th>Owner</th></tr>"
    foreach ($row in $Data) {
        $impactClass = $row.Impact.ToLower()
        $killClass = if ($row.Killable) { "killable" } else { "protected" }
        $killText = if ($row.Killable) { "Yes" } else { "Protected" }
        $relClass = $row.Relevance.ToLower()
        $htmlBody += "<tr><td>$($row.Name)</td><td>$($row.PID)</td><td>$($row.Category)</td><td class='$relClass'>$($row.Relevance)</td><td>$($row.Mem_MB)</td><td>$($row.CPU_Sec)</td><td class='$impactClass'>$($row.Impact)</td><td class='$killClass'>$killText</td><td>$($row.RuntimeStr)</td><td>$($row.Owner)</td></tr>"
    }
    $htmlBody += "</table></body></html>"
    ($htmlHead + $htmlBody) | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Host "  Exported HTML: $htmlPath" -ForegroundColor Green
    $open = Read-Host "  Open HTML report in browser? (y/N)"
    if ($open -eq "y") { Start-Process $htmlPath }
}

function Option-NetworkActivity {
    Write-Host "`n  ── NETWORK ACTIVITY ──" -ForegroundColor Yellow
    Write-Host "  Processes with active TCP connections:" -ForegroundColor DarkGray
    try {
        $netConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Group-Object OwningProcess |
            ForEach-Object {
                $proc = Get-Process -Id $_.Name -ErrorAction SilentlyContinue
                $conns = $_.Group
                $remoteAddrs = ($conns | Select-Object -ExpandProperty RemoteAddress -Unique | Select-Object -First 5) -join ", "
                [PSCustomObject]@{
                    Name          = if ($proc) { $proc.ProcessName } else { "PID $($_.Name)" }
                    PID           = [int]$_.Name
                    Connections   = $_.Count
                    "Mem_MB"      = if ($proc) { [math]::Round($proc.WorkingSet64/1MB,1) } else { 0 }
                    RemoteTargets = $remoteAddrs
                    Ports         = ($conns | Select-Object -ExpandProperty RemotePort -Unique | Select-Object -First 5) -join ", "
                }
            } | Sort-Object Connections -Descending
        if ($netConns) {
            $netConns | Format-Table -AutoSize
            Write-Host "  Total: $($netConns.Count) processes with active connections" -ForegroundColor DarkGray
        } else { Write-Host "  No active network connections found." -ForegroundColor Green }
    } catch {
        Write-Host "  Get-NetTCPConnection not available. Falling back to netstat..." -ForegroundColor DarkYellow
        Write-Host "  Run 'netstat -b -n' in an admin terminal for network details." -ForegroundColor DarkGray
    }
}

function Option-DiskIO {
    Write-Host "`n  ── DISK I/O ANALYSIS ──" -ForegroundColor Yellow
    Write-Host "  Processes with disk read/write activity:" -ForegroundColor DarkGray
    try {
        $ioData = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $io = $_.Handle  # trigger access
            try {
                $perf = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -Filter "IDProcess=$($_.Id)" -ErrorAction SilentlyContinue
                if ($perf -and ($perf.IOReadBytesPersec -gt 0 -or $perf.IOWriteBytesPersec -gt 0)) {
                    [PSCustomObject]@{
                        Name         = $_.ProcessName
                        PID          = $_.Id
                        "Read_MBps"  = [math]::Round($perf.IOReadBytesPersec / 1MB, 2)
                        "Write_MBps" = [math]::Round($perf.IOWriteBytesPersec / 1MB, 2)
                        "Total_MBps" = [math]::Round(($perf.IOReadBytesPersec + $perf.IOWriteBytesPersec) / 1MB, 2)
                        "Mem_MB"     = [math]::Round($_.WorkingSet64 / 1MB, 1)
                    }
                }
            } catch { }
        } | Where-Object { $_ } | Sort-Object Total_MBps -Descending | Select-Object -First 30
        if ($ioData) {
            $ioData | Format-Table -AutoSize
        } else {
            Write-Host "  No significant disk I/O detected (or WMI perf counters unavailable)." -ForegroundColor DarkGray
            Write-Host "  Alternative: Open Resource Monitor (resmon.exe) → Disk tab for real-time I/O." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  Disk I/O query failed: $_" -ForegroundColor Red
        Write-Host "  Try: resmon.exe → Disk tab for real-time disk activity." -ForegroundColor DarkGray
    }
}

function Option-ProcessTree {
    param($Data)
    Write-Host "`n  ── PROCESS TREE ──" -ForegroundColor Yellow
    Write-Host "  Showing parent → child relationships:`n" -ForegroundColor DarkGray

    $pidMap = @{}
    foreach ($p in $Data) { $pidMap[$p.PID] = $p }

    # Find root processes (no parent or parent not in our list)
    $roots = $Data | Where-Object { !$_.ParentPID -or !$pidMap.ContainsKey($_.ParentPID) }
    $children = $Data | Group-Object ParentPID

    $childMap = @{}
    foreach ($g in $children) {
        if ($g.Name) { $childMap[[int]$g.Name] = $g.Group }
    }

    function Print-Tree {
        param($Proc, [string]$Indent = "", [bool]$Last = $true)
        $connector = if ($Last) { "└── " } else { "├── " }
        $memColor = if ($Proc.Mem_MB -gt 200) { "Red" } elseif ($Proc.Mem_MB -gt 50) { "Yellow" } else { "DarkGray" }
        Write-Host ("  {0}{1}{2} (PID {3}) [{4}] {5}MB" -f $Indent, $connector, $Proc.Name, $Proc.PID, $Proc.Category, $Proc.Mem_MB) -ForegroundColor $memColor
        $kids = $childMap[$Proc.PID]
        if ($kids) {
            $nextIndent = $Indent + $(if ($Last) { "    " } else { "│   " })
            for ($i = 0; $i -lt $kids.Count; $i++) {
                Print-Tree $kids[$i] $nextIndent ($i -eq $kids.Count - 1)
            }
        }
    }

    # Show top-level trees sorted by total memory
    $topRoots = $roots | Sort-Object Mem_MB -Descending | Select-Object -First 30
    foreach ($root in $topRoots) {
        Print-Tree $root "" $true
    }
    Write-Host "`n  Showing top 30 root processes. Colors: Red >200MB, Yellow >50MB, Gray <50MB" -ForegroundColor DarkGray
}

function Option-StartupAnalysis {
    Write-Host "`n  ── STARTUP PROGRAMS ANALYSIS ──" -ForegroundColor Yellow
    Write-Host "  Scanning all auto-start locations...`n" -ForegroundColor DarkGray

    # Registry Run keys
    $locations = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Scope = "All Users" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Scope = "Current User" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "All Users (Once)" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "Current User (Once)" }
    )

    $startupItems = @()
    foreach ($loc in $locations) {
        try {
            $items = Get-ItemProperty -Path $loc.Path -ErrorAction SilentlyContinue
            if ($items) {
                $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                    $startupItems += [PSCustomObject]@{
                        Name     = $_.Name
                        Location = $loc.Scope
                        Source   = "Registry"
                        Command  = $_.Value.ToString().Substring(0, [Math]::Min(100, $_.Value.ToString().Length))
                    }
                }
            }
        } catch { }
    }

    # Startup folder
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem $folder -ErrorAction SilentlyContinue | ForEach-Object {
                $startupItems += [PSCustomObject]@{
                    Name     = $_.BaseName
                    Location = if ($folder -like "*ProgramData*") { "All Users" } else { "Current User" }
                    Source   = "Startup Folder"
                    Command  = $_.FullName
                }
            }
        }
    }

    # Scheduled tasks that run at logon
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.State -ne "Disabled" -and
            ($_.Triggers | Where-Object { $_ -is [CimInstance] -and $_.CimClass.CimClassName -eq "MSFT_TaskLogonTrigger" })
        } | ForEach-Object {
            $action = ($_.Actions | Select-Object -First 1).Execute
            $startupItems += [PSCustomObject]@{
                Name     = $_.TaskName
                Location = "Logon Task"
                Source   = "Task Scheduler"
                Command  = if ($action) { $action.Substring(0, [Math]::Min(100, $action.Length)) } else { "N/A" }
            }
        }
    } catch { }

    if ($startupItems) {
        Write-Host "  Found $($startupItems.Count) startup entries:`n" -ForegroundColor Cyan
        $startupItems | Format-Table -AutoSize -Wrap
        Write-Host "  Tip: Use Autoruns (Sysinternals) for the most comprehensive startup view." -ForegroundColor DarkGray
        Write-Host "  Tip: To disable a registry startup item:" -ForegroundColor DarkGray
        Write-Host '    Remove-ItemProperty -Path "HKCU:\...\Run" -Name "ItemName"' -ForegroundColor DarkGray
    } else {
        Write-Host "  No startup items found (unusual — run as admin for full visibility)." -ForegroundColor DarkYellow
    }
}

function Option-RelevanceBreakdown {
    param($Data)
    Write-Host "`n  ── RELEVANCE BREAKDOWN ──" -ForegroundColor Yellow
    Write-Host "  How relevant is each process to your current session?`n" -ForegroundColor DarkGray

    $groups = $Data | Group-Object Relevance
    $order = @("ESSENTIAL", "ACTIVE", "PASSIVE", "UNKNOWN", "BLOAT")
    foreach ($level in $order) {
        $g = $groups | Where-Object { $_.Name -eq $level }
        if (!$g) { continue }
        $totalMem = [math]::Round(($g.Group | Measure-Object Mem_MB -Sum).Sum, 1)
        $color = switch ($level) {
            "ESSENTIAL" { "Cyan" }
            "ACTIVE"    { "Green" }
            "PASSIVE"   { "DarkYellow" }
            "UNKNOWN"   { "Yellow" }
            "BLOAT"     { "Red" }
        }
        $desc = switch ($level) {
            "ESSENTIAL" { "System will break without these" }
            "ACTIVE"    { "You are actively using these (CPU > 0)" }
            "PASSIVE"   { "Running but not actively used right now" }
            "UNKNOWN"   { "Uncategorized — review these manually" }
            "BLOAT"     { "Likely unnecessary — safe to kill" }
        }
        Write-Host ("  {0,-12} {1,3} procs | {2,8} MB — {3}" -f $level, $g.Count, $totalMem, $desc) -ForegroundColor $color
    }

    Write-Host ""
    $expand = Read-Host "  Expand a level? (ESSENTIAL/ACTIVE/PASSIVE/UNKNOWN/BLOAT or Enter to skip)"
    if ($expand) {
        $match = $Data | Where-Object { $_.Relevance -eq $expand.ToUpper() }
        if ($match) { Display-Table $match } else { Write-Host "  No match." -ForegroundColor Red }
    }
}

function Option-RestorePoint {
    Write-Host "`n  ── CREATE SYSTEM RESTORE POINT ──" -ForegroundColor Yellow
    Write-Host "  This creates a snapshot you can roll back to if something goes wrong." -ForegroundColor DarkGray
    $desc = Read-Host "  Description (default: 'Before Process Cleanup')"
    if (!$desc) { $desc = "Before Process Cleanup" }
    try {
        Checkpoint-Computer -Description $desc -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Host "  ✓ Restore point '$desc' created successfully!" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        Write-Host "  Common causes: not running as admin, or restore points disabled." -ForegroundColor DarkGray
        Write-Host "  Enable: SystemPropertiesProtection.exe → select C: → Configure → Turn on" -ForegroundColor DarkGray
    }
}

# ── Main Loop ──
$processData = $null

Show-Banner
Write-Host "  Loading process data..." -ForegroundColor DarkGray
$processData = Collect-ProcessData
Write-Host "  Loaded $($processData.Count) processes.`n" -ForegroundColor Green

Show-Banner $processData

while ($true) {
    Show-Menu
    $choice = Read-Host "  Select option"
    while ($true) {
        switch ($choice) {
            "1"  { Option-FullReport $processData }
            "2"  { Option-ByCategory $processData }
            "3"  { Option-TopHogs $processData }
            "4"  { Option-ImpactAnalysis $processData }
            "5"  { Option-LongRunning $processData }
            "6"  { Option-Uncategorized $processData }
            "7"  { Option-Search $processData }
            "8"  { Option-KillProcess $processData }
            "9"  { Option-KillByCategory $processData }
            "10" { Option-Export $processData }
            "11" { Option-NetworkActivity }
            "12" { Option-DiskIO }
            "13" { Option-ProcessTree $processData }
            "14" { Option-StartupAnalysis }
            "15" { Option-RelevanceBreakdown $processData }
            "16" { Option-RestorePoint }
            "17" { $processData = Collect-ProcessData; Write-Host "  Refreshed $($processData.Count) processes." -ForegroundColor Green }
            "?"  { Show-Help }
            "0"  { Write-Host "`n  Goodbye!`n" -ForegroundColor Cyan; exit }
            default { Write-Host "  Invalid option. Type [?] for help." -ForegroundColor Red }
        }
        Write-Host ""
        Write-Host "  Press Enter for menu, or type next option directly:" -ForegroundColor DarkGray -NoNewline
        $next = Read-Host " "
        if ($next) {
            # User typed a command directly — process it without redrawing the full menu
            $choice = $next
            Show-Banner $processData -NoClear
        } else { break }
    }
    Show-Banner $processData
}

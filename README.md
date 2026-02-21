# Windows Process Audit & Debloat Toolkit

> A comprehensive collection of scripts and tools for auditing, analyzing, debloating, and cleaning up your Windows laptop.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Script 1: ProcessAudit.ps1](#script-1-processauditps1)
  - [Features](#processaudit-features)
  - [Menu Options](#processaudit-menu-options)
  - [Category System](#category-system)
  - [Relevance Scoring](#relevance-scoring)
  - [Impact Levels](#impact-levels)
  - [Customizing Categories](#customizing-categories)
  - [Export Formats](#export-formats)
- [Script 2: ZombieDetector.ps1](#script-2-zombiedetectorps1)
  - [What Are "Zombie" Processes on Windows?](#what-are-zombie-processes-on-windows)
  - [The 7 Detection Engines](#the-7-detection-engines)
  - [Menu Options](#zombiedetector-menu-options)
  - [Configurable Thresholds](#configurable-thresholds)
  - [Kill Modes](#kill-modes)
  - [Safety System](#safety-system)
  - [Unattended / Scheduled Mode](#unattended--scheduled-mode)
- [Windows Debloating Tools](#windows-debloating-tools)
  - [Win11Debloat](#1-win11debloat-by-raphire)
  - [Chris Titus WinUtil](#2-chris-titus-winutil)
  - [BloatyNosy](#3-bloatynosy-by-builtbybel)
  - [Comparison Table](#debloating-tools-comparison)
- [Also Worth Knowing About](#also-worth-knowing-about)
  - [Process Explorer](#process-explorer-sysinternals)
  - [Process Monitor](#process-monitor-sysinternals)
  - [Autoruns](#autoruns-sysinternals)
- [How to Run the Scripts](#how-to-run-the-scripts)
- [Troubleshooting](#troubleshooting)
- [Windows 10 vs Windows 11 Differences](#windows-10-vs-windows-11-differences)
- [What to Do After Finding Issues](#what-to-do-after-finding-issues)
- [Frequently Asked Questions](#frequently-asked-questions)
- [Safety & Disclaimer](#safety--disclaimer)

---

## Overview

This toolkit addresses three core needs:

| Need | Solution |
|------|----------|
| **Understand what's running** | `ProcessAudit.ps1` — segments every process by category, usage, impact, and runtime |
| **Find and kill zombie processes** | `ZombieDetector.ps1` — 7 detection engines for hung, orphaned, idle, hidden, suspended, ghost, and duplicate processes |
| **Remove Windows bloatware** | Curated list of trusted open-source debloating tools |

---

## Quick Start

```powershell
# Open PowerShell as Administrator, then:
Set-ExecutionPolicy Unrestricted -Scope Process -Force

# Run the Process Auditor
.\ProcessAudit.ps1

# Run the Zombie Detector
.\ZombieDetector.ps1
```

Both scripts show a health dashboard on launch and a grouped menu. Type `?` at any menu for a guided workflow. You can chain commands — after any action, type the next option number directly instead of pressing Enter to return to the menu.

---

## Script 1: ProcessAudit.ps1

An interactive, menu-driven PowerShell script that gives you complete visibility and control over every process running on your Windows machine.

On launch, you see a health dashboard showing total processes, memory usage, high-impact count, bloat count, and not-responding count — so you immediately know if something needs attention. The menu is grouped into ANALYZE, DEEP DIVE, and TAKE ACTION sections. Type `?` for a guided first-time workflow.

### ProcessAudit Features

- **Full process inventory** with memory, CPU, runtime, owner, command line, thread count, and handle count
- **Smart categorization** — 60+ known processes mapped to categories like `System/Critical`, `Browser/Chrome`, `Bloat/Cortana`, `Dev/VSCode`, etc.
- **Relevance scoring** — every process rated as ESSENTIAL, ACTIVE, PASSIVE, UNKNOWN, or BLOAT based on category and activity
- **Impact scoring** — every process rated as CRITICAL, HIGH, MEDIUM, LOW, or MINIMAL based on resource consumption
- **Safety flags** — each category marked as `Killable` or `Protected` to prevent you from accidentally crashing your system
- **Network activity** — see which processes have active TCP connections and where they're connecting
- **Disk I/O analysis** — identify processes hammering your disk with reads/writes
- **Process tree** — visual parent-child relationship view with memory color coding
- **Startup analysis** — scan registry Run keys, startup folders, and scheduled tasks for auto-start programs
- **Interactive kill** — kill individual processes or entire categories, with confirmation prompts and safety warnings
- **System restore point creation** — create a safety snapshot before making changes
- **Export** — CSV for spreadsheets, styled HTML report for visual review
- **Search** — find processes by name, category, or command line content

### ProcessAudit Menu Options

| Option | Description |
|--------|-------------|
| **1 — Full Process Report** | Lists all processes with sorting options (Memory, CPU, Runtime, Name, Category). Choose to see top 50 or all. |
| **2 — View by Category** | Groups processes by category, shows total memory/CPU per group, color-coded as KILLABLE (green) or PROTECTED (red). Expand any category for details. |
| **3 — Top Resource Hogs** | Shows the top N processes by memory and CPU separately. You choose how many to display. |
| **4 — Impact Analysis** | Filters to only CRITICAL and HIGH impact processes. Shows total memory consumed by high-impact processes. |
| **5 — Long-Running Processes** | Finds processes running longer than a threshold you specify (default 24 hours). Sorted by runtime. |
| **6 — Uncategorized Processes** | Shows processes not in the known category map — these are the ones you should review for potential bloat or unknown software. |
| **7 — Search** | Free-text search across process name, category, and command line. Shows matching processes with their full command lines. |
| **8 — Kill a Process** | Enter a PID or name. Shows safety status before killing. Protected processes require typing 'FORCE' to override. |
| **9 — Kill by Category** | Lists all killable categories with process counts and memory totals. Select multiple categories by number for batch termination. |
| **10 — Export** | Generates timestamped CSV and styled HTML reports to `Desktop\ProcessAudit\`. Option to open HTML in browser. Includes Relevance column. |
| **11 — Network Activity** | Shows all processes with active TCP connections, connection counts, remote targets, and ports. Identifies what's phoning home. |
| **12 — Disk I/O Analysis** | Shows processes with active disk read/write activity in MB/s. Identifies what's hammering your disk. Falls back to Resource Monitor guidance if WMI counters unavailable. |
| **13 — Process Tree** | Visual parent→child tree view of all processes. Color-coded by memory usage (Red >200MB, Yellow >50MB, Gray <50MB). Shows top 30 root processes. |
| **14 — Startup Programs** | Scans registry Run keys (HKLM + HKCU), startup folders, and scheduled logon tasks. Shows what auto-starts and where it's configured. |
| **15 — Relevance Breakdown** | Groups all processes by relevance (ESSENTIAL → BLOAT) with memory totals. Expand any level to see individual processes. |
| **16 — Create Restore Point** | Creates a Windows System Restore Point before you make changes. Includes error guidance if restore points are disabled. |
| **17 — Refresh Data** | Re-scans all processes to get current data. |

### Category System

Processes are mapped to categories using a customizable hashtable at the top of the script. The default mappings include:

| Category | Examples | Killable? |
|----------|----------|-----------|
| `System/Critical` | csrss, smss, wininit, winlogon | ❌ No — will crash Windows |
| `System/Security` | lsass | ❌ No — handles authentication |
| `System/ServiceHost` | svchost | ❌ No — hosts Windows services |
| `System/Kernel` | System, Idle, Registry, Memory Compression | ❌ No |
| `Shell/UI` | explorer, ShellExperienceHost | ✅ Yes (explorer restarts automatically) |
| `Shell/Compositor` | dwm (Desktop Window Manager) | ❌ No — handles all screen rendering |
| `Search/Indexing` | SearchHost, SearchIndexer | ✅ Yes |
| `Security/Defender` | MsMpEng, NisSrv | ❌ No — your antivirus |
| `Cloud/OneDrive` | OneDrive | ✅ Yes |
| `Communication/Teams` | Teams | ✅ Yes |
| `Bloat/PhoneLink` | PhoneExperienceHost, YourPhone | ✅ Yes |
| `Bloat/GameBar` | GameBar, gameinputsvc | ✅ Yes |
| `Bloat/Cortana` | Cortana | ✅ Yes |
| `Bloat/AI` | Copilot | ✅ Yes |
| `Browser/*` | chrome, msedge, firefox, brave, opera | ✅ Yes |
| `Dev/*` | Code, node, python, java, docker, git | ✅ Yes |
| `Communication/*` | Slack, Discord, Zoom | ✅ Yes |
| `Media/Spotify` | Spotify | ✅ Yes |
| `Hardware/*` | NVIDIA, AMD, Realtek Audio | Varies |
| `Uncategorized` | Anything not in the map | ✅ Yes (review first) |

### Impact Levels

| Level | Criteria | Color in HTML |
|-------|----------|---------------|
| **CRITICAL** | Memory > 1000 MB OR CPU > 600 seconds | Red |
| **HIGH** | Memory > 500 MB OR CPU > 300 seconds | Orange |
| **MEDIUM** | Memory > 100 MB OR CPU > 60 seconds | Yellow |
| **LOW** | Memory > 20 MB | Green |
| **MINIMAL** | Memory ≤ 20 MB | Dark Green |

### Relevance Scoring

Every process gets a relevance score answering: "How important is this to my current session?"

| Level | Meaning | Action |
|-------|---------|--------|
| **ESSENTIAL** | System/Security/Shell processes — Windows breaks without them | Never kill |
| **ACTIVE** | Has CPU activity > 5 seconds — you're actively using it | Keep running |
| **PASSIVE** | Running but no recent CPU activity — background process | Review if needed |
| **UNKNOWN** | Uncategorized process — can't determine relevance | Investigate manually |
| **BLOAT** | Categorized as bloat, or not responding | Safe to kill |

The relevance breakdown (menu option 15) shows total memory per level, helping you see how much RAM is consumed by processes you don't actually need.

### Customizing Categories

Edit the `$CategoryMap` hashtable at the top of `ProcessAudit.ps1` to add your own software:

```powershell
# Add your own entries:
$CategoryMap = [ordered]@{
    # ... existing entries ...
    
    # Your custom additions:
    "MyCompanyVPN"    = @{ Category = "Work/VPN";        Killable = $true }
    "Notion"          = @{ Category = "Productivity";    Killable = $true }
    "obs64"           = @{ Category = "Media/Streaming"; Killable = $true }
    "steam"           = @{ Category = "Gaming/Steam";    Killable = $true }
}
```

Wildcard matching is supported — `"NVIDIA*"` matches any process starting with "NVIDIA".

### Export Formats

**CSV** — Opens in Excel, Google Sheets, or any spreadsheet tool. Contains all columns including command line. Perfect for filtering and pivot tables.

**HTML** — Dark-themed, styled report with color-coded impact levels and killable status. Hover effects on rows. Opens in any browser. Great for sharing or archiving.

Both are saved to `Desktop\ProcessAudit\` with timestamps.

---

## Script 2: ZombieDetector.ps1

An interactive script with 7 specialized detection engines that find different types of zombie-like processes on Windows.

Unlike v2, the detector does NOT auto-scan on launch — it starts instantly and lets you choose what to scan. A summary dashboard shows results from your last scan. The menu is grouped into SCAN and TAKE ACTION sections. Type `?` for a guided workflow.

### What Are "Zombie" Processes on Windows?

Windows doesn't have "zombie processes" in the Unix/Linux sense (where a child process has terminated but its entry remains in the process table). However, Windows has several equivalent problems:

| Type | Description | Risk |
|------|-------------|------|
| **Not Responding** | Process is hung, not processing Windows messages | Wastes memory, may hold file locks |
| **Orphaned** | Parent process has exited, child is still running with no supervision | Resource leak, may never terminate |
| **Idle Long-Runner** | Running for days with zero CPU usage — doing nothing | Wastes memory |
| **Hidden Resource Hog** | No visible window but consuming significant memory | Stealth resource drain |
| **All Threads Suspended** | Every thread in the process is suspended — effectively dead | Wastes memory and handles |
| **Ghost Service** | Windows service is "Stopped" but its process is still alive | Confusing state, resource waste |
| **Excessive Duplicates** | 10+ instances of the same process (e.g., browser tabs gone wild) | Memory leak, possible runaway |

### The 7 Detection Engines

#### Engine 1: Not Responding
- Uses `Process.Responding` property
- Detects processes that have stopped processing their Windows message queue
- Severity: **HIGH** — these are genuinely hung

#### Engine 2: Orphaned Processes
- Compares each process's `ParentProcessId` against all running PIDs
- If the parent PID doesn't exist anymore, the process is orphaned
- Filters out system processes that are normally "orphaned" by design
- Severity: **MEDIUM**

#### Engine 3: Idle Long-Runners
- Finds processes with exactly 0 CPU seconds that have been running longer than a configurable threshold (default: 24 hours)
- These processes started, did something, and have been sitting idle ever since
- Severity: **LOW** (they're not actively harmful, just wasteful)

#### Engine 4: Hidden Resource Hogs
- Finds processes with no visible window (`MainWindowHandle -eq 0`) consuming more than a configurable memory threshold (default: 50 MB)
- Excludes known system processes that legitimately run without windows
- Severity: **HIGH** if >200 MB, **MEDIUM** otherwise

#### Engine 5: Suspended Threads
- Checks if ALL threads in a process have `WaitReason -eq "Suspended"`
- A process where every single thread is suspended is effectively dead
- Severity: **MEDIUM**

#### Engine 6: Ghost Services
- Cross-references `Get-Service` (stopped services) with `Win32_Service` (process IDs)
- If a service is marked as "Stopped" but its process ID is still alive and running, that's a ghost
- Severity: **MEDIUM**

#### Engine 7: Excessive Duplicates
- Groups processes by name and flags any with more than 10 instances
- Common culprits: browser helper processes, runtime brokers, background task hosts
- Shows total memory consumed across all instances
- Severity: **HIGH** if total >500 MB, **MEDIUM** otherwise

### ZombieDetector Menu Options

| Option | Description |
|--------|-------------|
| **1 — Full Zombie Scan** | Runs all 7 detection engines and displays combined results grouped by type |
| **2-8 — Individual Scans** | Run any single detection engine in isolation |
| **9 — Kill Zombies (interactive)** | Shows numbered list of all detected zombies. Select specific ones by number, 'all' for safe ones, or 'none' to cancel |
| **10 — Kill ALL Safe Zombies** | Batch kills every zombie marked as safe. Shows potential memory recovery. Requires typing 'KILL ALL' to confirm |
| **11 — Export Zombie Report** | CSV + styled HTML report with severity color coding. Saved to `Desktop\ProcessAudit\` |
| **12 — Configure Thresholds** | Change idle hours threshold and hidden memory threshold without editing the script |

### Configurable Thresholds

| Threshold | Default | What It Controls |
|-----------|---------|------------------|
| Idle Hours | 24 | How long a process must be running with 0 CPU to be flagged as idle |
| Hidden Memory MB | 50 | Minimum memory for a windowless process to be flagged as a hidden hog |

Change these interactively via menu option 12, or when running individual scans (options 4 and 5 prompt you).

### Kill Modes

**Interactive Kill (Option 9)**
1. Displays all zombies with numbered list
2. Shows severity, name, PID, memory, and detail for each
3. You select by number (comma-separated), 'all', or 'none'
4. Confirmation prompt before any killing
5. Reports success/failure for each process

**Batch Kill (Option 10)**
1. Filters to only processes marked as `Safe = $true`
2. Shows the full list and total potential memory recovery
3. Requires typing exactly `KILL ALL` to proceed
4. Reports killed count and failed count

### Safety System

The script maintains a `$SafeIgnoreList` of processes that are always excluded from zombie detection:

```
Idle, System, Registry, Memory Compression, smss, csrss, wininit,
winlogon, lsass, services, svchost, fontdrvhost, dwm, conhost,
WmiPrvSE, dllhost, sihost, taskhostw, RuntimeBroker,
backgroundTaskHost, SecurityHealthSystray, ctfmon, TextInputHost
```

Each detected zombie also has a `Safe` flag:
- `Safe = $true` — can be killed without system impact
- `Safe = $false` — killing may have side effects (e.g., excessive duplicates where you don't want to kill ALL instances)

You can edit `$SafeIgnoreList` at the top of the script to add processes you want to always ignore.

### Unattended / Scheduled Mode

The script supports a `-AutoExport` flag for running without user interaction:

```powershell
.\ZombieDetector.ps1 -AutoExport
```

This will:
1. Run all 7 detection engines with default thresholds
2. Export CSV and HTML reports to `Desktop\ProcessAudit\` with `_Auto_` in the filename
3. Exit immediately — no menu, no prompts

To schedule this as a daily task:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Tools\ZombieDetector.ps1 -AutoExport"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -TaskName "ZombieDetector-Daily" -Action $action -Trigger $trigger -RunLevel Highest -Description "Daily zombie process scan"
```

Reports accumulate in `Desktop\ProcessAudit\` with timestamps, so you can compare across days.

---

## Windows Debloating Tools

### 1. Win11Debloat (by Raphire)

**The most recommended lightweight debloating script.**

- **GitHub:** https://github.com/Raphire/Win11Debloat
- **Type:** PowerShell script
- **Compatibility:** Windows 10 & 11
- **License:** MIT

**Quick Run:**
```powershell
& ([scriptblock]::Create((irm "https://debloat.raphi.re/")))
```

**What it does:**
- Removes pre-installed bloatware apps (Candy Crush, Xbox, Mail, etc.)
- Disables telemetry, diagnostic data, activity history, targeted ads
- Disables tips, tricks, suggestions & ads across Windows
- Disables/removes Microsoft Copilot and AI features
- Restores old Windows 10 context menu on Win11
- Disables Bing search in Start Menu
- Removes widgets, Cortana, Phone Link
- Disables Xbox Game Bar
- Configures taskbar, File Explorer, and Start Menu
- Supports command-line parameters for automation
- All changes are reversible

**Best for:** Users who want a quick, safe, one-click debloat with the option to customize.

---

### 2. Chris Titus WinUtil

**The most feature-rich all-in-one Windows utility.**

- **GitHub:** https://github.com/ChrisTitusTech/winutil
- **Type:** PowerShell script with GUI
- **Compatibility:** Windows 10 & 11
- **Documentation:** https://winutil.christitus.com/

**Quick Run:**
```powershell
# Stable
irm "https://christitus.com/win" | iex

# Dev branch
irm "https://christitus.com/windev" | iex
```

**What it does:**
- **Install tab** — bulk install popular software (browsers, dev tools, media players, etc.)
- **Tweaks tab** — debloat, disable telemetry, optimize performance, power settings
- **Config tab** — troubleshoot common Windows issues, fix Windows Update
- **Updates tab** — manage Windows Update behavior

**Best for:** Power users who want a GUI-based all-in-one tool that goes beyond just debloating.

---

### 3. BloatyNosy (by builtbybel)

**Lightweight native .exe debloater.**

- **GitHub:** https://github.com/builtbybel/Bloatynosy
- **Type:** Native Windows application (.exe)
- **Compatibility:** Primarily Windows 11, partial Windows 10 support

**What it does:**
- Native app — no web dependencies, no PowerShell required
- Focused on essential debloating tasks
- No AI/Copilot integration (ironic, given it removes AI bloat)
- Clean, simple interface
- Includes "Fresh11" OOBE assistant for new Windows installs

**Best for:** Users who prefer a simple GUI app over running PowerShell scripts.

---

### Debloating Tools Comparison

| Feature | Win11Debloat | Chris Titus WinUtil | BloatyNosy |
|---------|:------------:|:-------------------:|:----------:|
| Interface | Terminal menu | GUI (WPF) | Native .exe GUI |
| App removal | ✅ | ✅ | ✅ |
| Telemetry disable | ✅ | ✅ | ✅ |
| AI/Copilot removal | ✅ | ✅ | ✅ |
| Software installer | ❌ | ✅ | ❌ |
| Windows Update mgmt | ✅ | ✅ | ❌ |
| Troubleshooting | ❌ | ✅ | ❌ |
| Command-line support | ✅ | ✅ | ❌ |
| Reversible changes | ✅ | Partial | Partial |
| Sysprep/Audit mode | ✅ | ❌ | ❌ |
| Requires PowerShell | Yes | Yes | No |
| Lightweight | ✅✅✅ | ✅ | ✅✅ |

---

## Also Worth Knowing About

### Process Explorer (Sysinternals)

**The gold standard for process inspection — far more powerful than Task Manager.**

- **Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
- **What it does:**
  - Shows process tree (parent-child relationships)
  - Displays all DLLs and handles loaded by each process
  - Color-coded process types (services, own processes, .NET, etc.)
  - GPU usage per process
  - VirusTotal integration — check any process against 70+ antivirus engines
  - Replace Task Manager entirely (Options → Replace Task Manager)
  - Find which process has a file or directory locked (Find → Find Handle or DLL)
  - Shows process CPU history graphs
- **Tip:** Run as Administrator for full visibility. Use Ctrl+L to show the lower pane with DLLs/handles for the selected process.

### Process Monitor (Sysinternals)

**Real-time monitoring of file system, registry, and process/thread activity.**

- **Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- **What it does:**
  - Captures every file read/write, registry access, network activity, and process event in real-time
  - Powerful filtering system — filter by process name, operation type, path, result, etc.
  - Essential for troubleshooting "why is this program slow" or "what files does this program access"
  - Process tree view showing all processes that ran during capture
  - Boot logging — capture activity from the moment Windows starts
- **Tip:** Always set filters before capturing, or you'll be overwhelmed with millions of events. Start with: Process Name → is → [your target] → Include.

### Autoruns (Sysinternals)

**Shows everything that auto-starts on your system — the ultimate startup manager.**

- **Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
- **What it does:**
  - Shows ALL auto-start locations: startup folders, Run keys, services, drivers, scheduled tasks, Winlogon, Explorer shell extensions, browser helpers, codecs, and more
  - Far more comprehensive than Task Manager's Startup tab (which only shows a fraction)
  - VirusTotal integration for every entry
  - Color coding: yellow = file not found, red = VirusTotal detection, pink = no publisher info
  - Disable entries without deleting them (uncheck the box)
  - Compare feature — save a baseline and compare later to see what changed
- **Tip:** Hide Microsoft and Windows entries (Options → Hide Microsoft Entries) to focus on third-party software. This is where you'll find the real bloat.

---

## How to Run the Scripts

### Prerequisites

- Windows 10 or Windows 11
- PowerShell 5.1 or later (pre-installed on all modern Windows)
- Administrator privileges (recommended for full process visibility)

### Step-by-Step

1. **Save the scripts** — Place `ProcessAudit.ps1` and `ZombieDetector.ps1` in a folder (e.g., `C:\Tools\`)

2. **Open PowerShell as Administrator:**
   - Press `Win + X` → select "Terminal (Admin)" or "PowerShell (Admin)"
   - Or: press `Win`, type "PowerShell", press `Ctrl + Shift + Enter`

3. **Enable script execution** (for current session only — safe, resets when you close the window):
   ```powershell
   Set-ExecutionPolicy Unrestricted -Scope Process -Force
   ```

4. **Navigate to the script folder:**
   ```powershell
   cd C:\Tools\
   ```

5. **Run the scripts:**
   ```powershell
   .\ProcessAudit.ps1
   .\ZombieDetector.ps1
   ```

### Running Without Admin

The scripts will still work without admin, but:
- Some system processes won't show CPU time or start time
- Process owner information may be unavailable for other users' processes
- Killing protected/system processes will fail

### Scheduling Regular Scans

The `-AutoExport` flag enables unattended operation. Create a scheduled task:

```powershell
# Daily zombie scan at 9 AM — exports CSV + HTML automatically
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Tools\ZombieDetector.ps1 -AutoExport"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -TaskName "ZombieDetector-Daily" -Action $action -Trigger $trigger -RunLevel Highest

# To remove the scheduled task later:
# Unregister-ScheduledTask -TaskName "ZombieDetector-Daily" -Confirm:$false
```

Reports are saved to `Desktop\ProcessAudit\` with timestamps so they don't overwrite each other.

---

## Troubleshooting

### Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| "Running scripts is disabled on this system" | PowerShell execution policy | Run `Set-ExecutionPolicy Unrestricted -Scope Process -Force` |
| "Access is denied" when killing a process | Not running as admin, or it's a system process | Right-click PowerShell → Run as Administrator |
| "Get-NetTCPConnection not available" | Older PowerShell version or missing module | Use `netstat -b -n` instead, or upgrade to PowerShell 5.1+ |
| Disk I/O shows no results | WMI performance counters disabled or unavailable | Open `resmon.exe` → Disk tab as alternative |
| "Cannot create restore point" | System Protection disabled or not admin | Run `SystemPropertiesProtection.exe` → select C: → Configure → Turn on |
| Script runs but shows very few processes | Not running as admin | Admin sees all processes; non-admin only sees own user's processes |
| "Checkpoint-Computer" fails with frequency error | Windows limits restore points to one per 24 hours | Wait 24 hours or use registry to override: `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore` → `SystemRestorePointCreationFrequency` = 0 |
| HTML report looks broken | File encoding issue | Ensure script saves as UTF-8; try opening in a different browser |
| Startup analysis shows nothing | Registry access restricted | Must run as admin to read HKLM keys |

### Script Won't Start At All

1. Verify PowerShell version: `$PSVersionTable.PSVersion` (need 5.1+)
2. Verify file isn't blocked: Right-click .ps1 → Properties → check "Unblock" if present
3. Try running directly: `powershell.exe -ExecutionPolicy Bypass -File .\ProcessAudit.ps1`

---

## Windows 10 vs Windows 11 Differences

### ProcessAudit.ps1

| Feature | Windows 10 | Windows 11 |
|---------|-----------|------------|
| Core functionality | ✅ Full | ✅ Full |
| Copilot/AI detection | N/A (no Copilot) | ✅ Detects Copilot processes |
| Widgets detection | N/A (no Widgets) | ✅ Detects Widget processes |
| Phone Link detection | ✅ YourPhone | ✅ PhoneExperienceHost |
| Network activity | ✅ Get-NetTCPConnection | ✅ Get-NetTCPConnection |
| Startup analysis | ✅ Full | ✅ Full |
| Process tree | ✅ Full | ✅ Full |

### ZombieDetector.ps1

| Feature | Windows 10 | Windows 11 |
|---------|-----------|------------|
| All 7 detection engines | ✅ Full | ✅ Full |
| Ghost services | ✅ Full | ✅ Full |
| Suspended threads | ✅ Full | ✅ Full |

### Debloating Tools

| Tool | Windows 10 | Windows 11 |
|------|-----------|------------|
| Win11Debloat | ✅ Supported | ✅ Full support |
| Chris Titus WinUtil | ✅ Full | ✅ Full |
| BloatyNosy | ⚠️ Partial (not all settings apply) | ✅ Primary target |

---

## What to Do After Finding Issues

### After Running ProcessAudit

1. **Check Relevance Breakdown (option 15)** — see how much memory is wasted on BLOAT and PASSIVE processes
2. **Review Uncategorized (option 6)** — research any unknown processes online before killing
3. **Check Startup Programs (option 14)** — disable unnecessary auto-start entries to speed up boot
4. **Export a baseline (option 10)** — save a report of your "clean" state for future comparison
5. **Kill bloat categories (option 9)** — batch kill Bloat/* categories to free memory immediately

### After Running ZombieDetector

1. **Start with NOT_RESPONDING** — these are genuinely hung and safe to kill immediately
2. **Review ORPHANED** — these are usually safe to kill; the parent that spawned them is already gone
3. **Check HIDDEN_HOGs** — research the process name before killing; some legitimate apps run without windows
4. **IDLE_LONGRUN** — low priority, but if you're low on memory, these are easy wins
5. **EXCESSIVE_DUPES** — don't kill all instances; investigate why there are so many (browser tabs? memory leak?)

### After Debloating

1. **Reboot** — many changes only take effect after restart
2. **Run ProcessAudit again** — verify the bloat is actually gone
3. **Check Windows Update** — make sure updates still work: Settings → Windows Update → Check for updates
4. **Test your apps** — open your commonly used applications to verify nothing broke
5. **Save a new restore point** — `Checkpoint-Computer -Description "After debloat - clean state"`

### Ongoing Maintenance

- Run ZombieDetector weekly (or set up the scheduled task)
- Run ProcessAudit monthly to catch new bloat from Windows updates
- After major Windows updates, re-run the debloating tool — Microsoft often re-enables telemetry and reinstalls removed apps
- Keep Autoruns handy — check it after installing new software to see what it added to startup

---

## Frequently Asked Questions

### Is it safe to kill processes marked as "Killable"?

Yes — killable processes are user-level applications that won't crash Windows. The worst that happens is you lose unsaved work in that application. Protected processes (marked red) are system-critical and should not be killed unless you know exactly what you're doing.

### Will debloating break Windows Update?

No — all three recommended debloating tools are careful not to break core Windows functionality. Win11Debloat explicitly states all changes are reversible.

### What's the difference between the Process Auditor and Task Manager?

Task Manager shows basic info. The Process Auditor adds:
- Smart categorization (60+ known processes)
- Impact scoring
- Safety flags (killable vs protected)
- Batch kill by category
- Command line visibility
- HTML/CSV export
- Uncategorized process detection (finds unknown software)

### How often should I run the Zombie Detector?

Run it whenever your system feels sluggish, or set up a weekly scheduled task. Most zombie processes accumulate over time as you use your computer without rebooting.

### Can I add my own process categories?

Yes — edit the `$CategoryMap` hashtable in `ProcessAudit.ps1` and the `$SafeIgnoreList` in `ZombieDetector.ps1`. Both are at the top of their respective scripts with clear formatting.

---

## Safety & Disclaimer

- These scripts are provided as-is for educational and productivity purposes
- Always run debloating tools on a system with a recent backup or restore point
- The kill functionality requires explicit confirmation (`YES`, `FORCE`, or `KILL ALL`) to prevent accidents
- Protected processes are marked to prevent accidental system crashes
- Test on a non-critical system first if you're unsure
- Create a System Restore Point before running debloating tools:
  ```powershell
  Checkpoint-Computer -Description "Before debloat" -RestorePointType MODIFY_SETTINGS
  ```

---

*Generated: 2026-02-21 | Toolkit Version: 3.0*

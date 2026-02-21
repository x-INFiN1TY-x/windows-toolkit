#!/bin/bash
# ============================================================================
# Git Setup Script for windows-toolkit
# ============================================================================
# This script initializes the repo with your PERSONAL GitHub account.
# It uses LOCAL git config only — your global Amazon employee config is UNTOUCHED.
#
# WHAT THIS DOES:
#   1. git init
#   2. Sets LOCAL user.name and user.email (only for this repo)
#   3. Adds all files and makes initial commit
#   4. Creates the GitHub repo and pushes
#
# WHAT THIS DOES NOT DO:
#   - Does NOT modify ~/.gitconfig (your Amazon employee config)
#   - Does NOT store your PAT in any file
#
# HOW TO REVERT TO YOUR EMPLOYEE ACCOUNT:
#   Just cd out of this directory. Your global git config is unchanged.
#   To verify: git config --global user.email  (should still show @amazon.com)
#
# USAGE:
#   cd ~/windows-toolkit
#   chmod +x setup-repo.sh
#   bash setup-repo.sh
#
# You will be prompted for your GitHub PAT when pushing.
# ============================================================================

set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

echo ""
echo "  ┌─────────────────────────────────────────────────┐"
echo "  │  Windows Toolkit — Git Repository Setup         │"
echo "  └─────────────────────────────────────────────────┘"
echo ""

# Safety check: show current global config
echo "  Your GLOBAL git config (will NOT be changed):"
echo "    Name:  $(git config --global user.name 2>/dev/null || echo 'not set')"
echo "    Email: $(git config --global user.email 2>/dev/null || echo 'not set')"
echo ""

# Initialize repo
if [ ! -d ".git" ]; then
    git init
    echo "  ✓ Git repo initialized"
else
    echo "  ✓ Git repo already exists"
fi

# Set LOCAL config (only affects this repo)
git config --local user.name "x-INFiN1TY-x"
git config --local user.email "your-personal-email@example.com"  # ← CHANGE THIS to your GitHub email
echo ""
echo "  ✓ LOCAL git config set (this repo only):"
echo "    Name:  $(git config --local user.name)"
echo "    Email: $(git config --local user.email)"
echo ""
echo "  ⚠  IMPORTANT: Edit the email above if needed:"
echo "     git config --local user.email \"your-real-email@example.com\""
echo ""

# Verify global is untouched
echo "  Verifying global config is untouched:"
echo "    Global Name:  $(git config --global user.name 2>/dev/null || echo 'not set')"
echo "    Global Email: $(git config --global user.email 2>/dev/null || echo 'not set')"
echo ""

# Stage and commit
git add -A
git commit -m "Initial commit: Windows Process Audit & Debloat Toolkit v3.0

- ProcessAudit.ps1: 17-option interactive process analyzer
  - Categorization, relevance scoring, impact analysis
  - Network activity, disk I/O, process tree, startup analysis
  - Interactive kill with safety system, batch kill by category
  - CSV + HTML export, system restore point creation

- ZombieDetector.ps1: 7-engine zombie process detector
  - Not responding, orphaned, idle, hidden, suspended, ghost, duplicates
  - Interactive and batch kill modes with safety flags
  - Configurable thresholds, unattended -AutoExport mode

- README.md: Comprehensive documentation
  - Full script documentation with all options
  - Debloating tools comparison (Win11Debloat, WinUtil, BloatyNosy)
  - Sysinternals tools guide
  - Troubleshooting, Win10 vs 11 differences, action guides"

echo ""
echo "  ✓ Initial commit created"
echo ""

# Remote setup
echo "  Now setting up GitHub remote..."
echo "  You'll need your GitHub PAT to push."
echo ""
echo "  Option A — HTTPS (recommended, uses PAT):"
echo "    git remote add origin https://github.com/x-INFiN1TY-x/windows-toolkit.git"
echo "    git branch -M main"
echo "    git push -u origin main"
echo ""
echo "  When prompted for password, paste your GitHub PAT."
echo ""
echo "  Option B — If you want to create the repo first via GitHub CLI:"
echo "    gh repo create windows-toolkit --public --source=. --remote=origin --push"
echo ""
echo "  ──────────────────────────────────────────────────────────"
echo "  ⚠  AFTER PUSHING: Rotate your GitHub PAT if you shared it"
echo "  ⚠  TO REVERT: Just cd out. Global git config is unchanged."
echo "  ──────────────────────────────────────────────────────────"
echo ""

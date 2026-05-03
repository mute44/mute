# MUTE installer for Windows
# Usage: irm https://raw.githubusercontent.com/YOUR_USERNAME/mute/main/install.ps1 | iex

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$REPO_RAW    = "https://raw.githubusercontent.com/YOUR_USERNAME/mute/main"
$INSTALL_DIR = "$env:USERPROFILE\.mute"
$VENV_DIR    = "$INSTALL_DIR\venv"
$PYTHON      = "$VENV_DIR\Scripts\python.exe"
$FILES       = @("mute.py", "crypto.py", "tor_transport.py", "check_integrity.py", "requirements.txt")

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step {
    param([string]$msg)
    Write-Host "  " -NoNewline
    Write-Host $msg -ForegroundColor White
}

function Write-Ok {
    param([string]$msg)
    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host "ok" -NoNewline -ForegroundColor Green
    Write-Host "] $msg" -ForegroundColor DarkGray
}

function Write-Fail {
    param([string]$msg)
    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host "!!" -NoNewline -ForegroundColor Red
    Write-Host "] $msg" -ForegroundColor Red
}

function Write-Header {
    Write-Host ""
    Write-Host "___  ___.     __    __     .___________.    _______ " -ForegroundColor White
    Write-Host "|   \/   |    |  |  |  |    |           |   |   ____|" -ForegroundColor White
    Write-Host "|  \  /  |    |  |  |  |    `---|  |----``   |  |__   " -ForegroundColor White
    Write-Host "|  |\/|  |    |  |  |  |        |  |        |   __|  " -ForegroundColor White
    Write-Host "|  |  |  |    |  ``--'  |        |  |        |  |____ " -ForegroundColor White
    Write-Host "|__|  |__|     \______/         |__|        |_______|" -ForegroundColor White
    Write-Host ""
    Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  installer" -ForegroundColor DarkGray
    Write-Host ""
}

# ─── Python check ─────────────────────────────────────────────────────────────

function Find-Python {
    $candidates = @("python", "python3", "python3.11", "python3.12", "python3.13")

    foreach ($cmd in $candidates) {
        try {
            $ver = & $cmd --version 2>&1
            if ($ver -match "Python (\d+)\.(\d+)") {
                $major = [int]$Matches[1]
                $minor = [int]$Matches[2]
                if ($major -eq 3 -and $minor -ge 11) {
                    return $cmd
                }
            }
        } catch {}
    }
    return $null
}

# ─── PATH helper ──────────────────────────────────────────────────────────────

function Add-ToUserPath {
    param([string]$dir)
    $current = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($current -split ";" -contains $dir) { return $false }
    [Environment]::SetEnvironmentVariable("PATH", "$current;$dir", "User")
    $env:PATH += ";$dir"
    return $true
}

# ─── Main ─────────────────────────────────────────────────────────────────────

Write-Header

# 1. Python
Write-Step "Checking Python 3.11+..."
$pyCmd = Find-Python

if (-not $pyCmd) {
    Write-Fail "Python 3.11+ not found."
    Write-Host ""
    Write-Host "  Install it with:" -ForegroundColor DarkGray
    Write-Host "    winget install Python.Python.3.11" -ForegroundColor Gray
    Write-Host "  or download from: https://python.org/downloads" -ForegroundColor Gray
    Write-Host "  Then re-run this installer." -ForegroundColor DarkGray
    Write-Host ""
    exit 1
}

$pyVer = & $pyCmd --version 2>&1
Write-Ok "Found: $pyVer ($pyCmd)"

# 2. Install dir
Write-Step "Creating install directory..."
if (-not (Test-Path $INSTALL_DIR)) {
    New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null
}
Write-Ok "$INSTALL_DIR"

# 3. Download files
Write-Step "Downloading MUTE..."
foreach ($file in $FILES) {
    $url  = "$REPO_RAW/$file"
    $dest = "$INSTALL_DIR\$file"
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
        Write-Ok "$file"
    } catch {
        Write-Fail "Failed to download $file"
        Write-Host "  URL: $url" -ForegroundColor DarkGray
        exit 1
    }
}

# 4. Venv
Write-Step "Creating virtual environment..."
if (Test-Path $VENV_DIR) {
    Remove-Item -Recurse -Force $VENV_DIR
}
& $pyCmd -m venv $VENV_DIR | Out-Null
Write-Ok "$VENV_DIR"

# 5. Dependencies
Write-Step "Installing dependencies (this may take a minute)..."
$pip = "$VENV_DIR\Scripts\pip.exe"
& $pip install --quiet --upgrade pip | Out-Null
& $pip install --quiet -r "$INSTALL_DIR\requirements.txt"
if ($LASTEXITCODE -ne 0) {
    Write-Fail "pip install failed. Check your internet connection and try again."
    exit 1
}
Write-Ok "pynacl, cryptography, stem, rich, prompt_toolkit"

# 6. Wrapper script
Write-Step "Creating mute.bat launcher..."
$bat = "@echo off`r`n`"$PYTHON`" `"$INSTALL_DIR\mute.py`" %*`r`n"
Set-Content -Path "$INSTALL_DIR\mute.bat" -Value $bat -Encoding ASCII
Write-Ok "$INSTALL_DIR\mute.bat"

# 7. PATH
Write-Step "Adding to PATH..."
$added = Add-ToUserPath $INSTALL_DIR
if ($added) {
    Write-Ok "Added $INSTALL_DIR to user PATH"
} else {
    Write-Ok "Already in PATH"
}

# 8. Integrity baseline
Write-Step "Generating integrity checksums..."
& $PYTHON "$INSTALL_DIR\check_integrity.py" --update | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Failed to generate integrity checksums."
    exit 1
}
Write-Ok "checksums.sha256 created"

# ─── Done ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  MUTE installed." -ForegroundColor White
Write-Host ""
Write-Host "  Restart your terminal, then run:" -ForegroundColor DarkGray
Write-Host "    mute" -ForegroundColor White
Write-Host ""
Write-Host "  To uninstall:" -ForegroundColor DarkGray
Write-Host "    Remove-Item -Recurse -Force $INSTALL_DIR" -ForegroundColor Gray
Write-Host "    (then remove $INSTALL_DIR from your user PATH)" -ForegroundColor DarkGray
Write-Host ""
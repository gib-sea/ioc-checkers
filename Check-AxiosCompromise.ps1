# ============================================================
# Axios npm Supply Chain Compromise - IOC Checker
# CVE: Axios 1.14.1 / 0.30.4 - March 31, 2026
# Checks for RAT artifacts dropped by malicious postinstall
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Axios Supply Chain Compromise - IOC Check" -ForegroundColor Cyan
Write-Host "  March 31, 2026 | axios 1.14.1 / 0.30.4  " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$compromised = $false
$findings = @()

# Check 1: Windows RAT artifact
$ratPath = "$env:PROGRAMDATA\wt.exe"
Write-Host "[*] Checking for Windows RAT artifact..." -ForegroundColor Yellow
if (Test-Path $ratPath) {
    Write-Host "[!] FOUND: $ratPath" -ForegroundColor Red
    $findings += "Windows RAT artifact found at $ratPath"
    $compromised = $true
} else {
    Write-Host "[+] Not found: $ratPath" -ForegroundColor Green
}

# Check 2: plain-crypto-js in common node_modules locations
Write-Host ""
Write-Host "[*] Scanning for plain-crypto-js in node_modules..." -ForegroundColor Yellow

$searchPaths = @(
    "$env:APPDATA\npm\node_modules",
    "$env:USERPROFILE\node_modules",
    "C:\Users\$env:USERNAME\AppData\Roaming\npm\node_modules",
    "$env:PROGRAMFILES\nodejs\node_modules"
)

$found = $false
foreach ($path in $searchPaths) {
    if (Test-Path "$path\plain-crypto-js") {
        Write-Host "[!] FOUND: $path\plain-crypto-js" -ForegroundColor Red
        $findings += "plain-crypto-js found at $path"
        $compromised = $true
        $found = $true
    }
}

# Also scan current directory and common project locations
$localCheck = Get-ChildItem -Path "C:\Users\$env:USERNAME" -Recurse -Directory -Filter "plain-crypto-js" -ErrorAction SilentlyContinue | Select-Object -First 5
if ($localCheck) {
    foreach ($item in $localCheck) {
        Write-Host "[!] FOUND: $($item.FullName)" -ForegroundColor Red
        $findings += "plain-crypto-js found at $($item.FullName)"
        $compromised = $true
        $found = $true
    }
}

if (-not $found) {
    Write-Host "[+] plain-crypto-js not found in common locations" -ForegroundColor Green
}

# Check 3: Compromised axios versions in package-lock files
Write-Host ""
Write-Host "[*] Scanning for compromised axios versions in lockfiles..." -ForegroundColor Yellow

$lockfiles = Get-ChildItem -Path "C:\Users\$env:USERNAME" -Recurse -Filter "package-lock.json" -ErrorAction SilentlyContinue | Select-Object -First 20
$axiosHit = $false
foreach ($lock in $lockfiles) {
    $content = Get-Content $lock.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match '"axios":\s*"1\.14\.1"' -or $content -match '"axios":\s*"0\.30\.4"') {
        Write-Host "[!] FOUND compromised axios version in: $($lock.FullName)" -ForegroundColor Red
        $findings += "Compromised axios version in $($lock.FullName)"
        $compromised = $true
        $axiosHit = $true
    }
}
if (-not $axiosHit) {
    Write-Host "[+] No compromised axios versions found in lockfiles" -ForegroundColor Green
}

# Check 4: Network connection to known C2
Write-Host ""
Write-Host "[*] Checking for active connections to known C2 (sfrclak.com)..." -ForegroundColor Yellow
$netstat = netstat -n 2>$null | Select-String "sfrclak"
if ($netstat) {
    Write-Host "[!] ACTIVE C2 CONNECTION DETECTED" -ForegroundColor Red
    $findings += "Active connection to C2 domain detected"
    $compromised = $true
} else {
    Write-Host "[+] No active C2 connections detected" -ForegroundColor Green
}

# Final verdict
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan

if ($compromised) {
    Write-Host ""
    Write-Host "  *** YOU'VE BEEN PWNED ***" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Indicators of compromise found:" -ForegroundColor Red
    foreach ($f in $findings) {
        Write-Host "  - $f" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  IMMEDIATE ACTIONS:" -ForegroundColor Yellow
    Write-Host "  1. Isolate this machine from the network NOW" -ForegroundColor Yellow
    Write-Host "  2. Do NOT attempt to clean in place - rebuild from known-good backup" -ForegroundColor Yellow
    Write-Host "  3. Rotate ALL credentials: npm tokens, AWS keys, SSH keys, cloud creds, .env values" -ForegroundColor Yellow
    Write-Host "  4. Review cloud access logs for unauthorized activity" -ForegroundColor Yellow
    Write-Host "  5. Report to your security team immediately" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "  You're clean, jelly bean." -ForegroundColor Green
    Write-Host ""
    Write-Host "  No IOCs found on this system." -ForegroundColor Green
    Write-Host "  Safe axios versions: 1.14.0 (1.x) or 0.30.3 (0.x)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Still recommended:" -ForegroundColor Yellow
    Write-Host "  - Pin your axios version explicitly in package.json" -ForegroundColor Yellow
    Write-Host "  - Run: npm install --ignore-scripts in CI environments" -ForegroundColor Yellow
    Write-Host "  - Enable npm provenance checking for critical packages" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "More info: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
Write-Host ""

# ============================================================
# Axios npm Supply Chain Compromise - IOC Checker
# Axios 1.14.1 / 0.30.4 - March 31, 2026
# Source: SANS Internet Storm Center / StepSecurity
# github.com/gib-sea/ioc-checkers
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Axios Supply Chain Compromise - IOC Check" -ForegroundColor Cyan
Write-Host "  March 31, 2026 | axios 1.14.1 / 0.30.4  " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$compromised = $false
$findings = @()

# Check 1: Windows RAT artifacts
Write-Host "[*] Checking for Windows RAT artifacts..." -ForegroundColor Yellow
$ratPaths = @(
    "$env:PROGRAMDATA\wt.exe",
    "$env:TEMP\6202033.vbs",
    "$env:TEMP\6202033.ps1"
)
foreach ($ratPath in $ratPaths) {
    if (Test-Path $ratPath) {
        Write-Host "[!] FOUND: $ratPath" -ForegroundColor Red
        $findings += "RAT artifact found at $ratPath"
        $compromised = $true
    } else {
        Write-Host "[+] Not found: $ratPath" -ForegroundColor Green
    }
}

# Check 2: plain-crypto-js in node_modules
Write-Host ""
Write-Host "[*] Scanning for plain-crypto-js in node_modules..." -ForegroundColor Yellow
$searchPaths = @(
    "$env:APPDATA\npm\node_modules",
    "$env:USERPROFILE\node_modules",
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
    Write-Host "[+] plain-crypto-js not found" -ForegroundColor Green
}

# Check 3: Compromised axios versions in lockfiles
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

# Check 4: Network connections to C2
Write-Host ""
Write-Host "[*] Checking for connections to known C2 (sfrclak.com / 142.11.206.73)..." -ForegroundColor Yellow
$netstat = netstat -n 2>$null | Select-String "sfrclak|142\.11\.206\.73"
if ($netstat) {
    Write-Host "[!] ACTIVE C2 CONNECTION DETECTED" -ForegroundColor Red
    $findings += "Active connection to C2 detected"
    $compromised = $true
} else {
    Write-Host "[+] No active C2 connections detected" -ForegroundColor Green
}

# Check 5: Known malicious package hashes
Write-Host ""
Write-Host "[*] Checking for known malicious file hashes..." -ForegroundColor Yellow
$maliciousHashes = @{
    "2553649f232204966871cea80a5d0d6adc700ca" = "axios@1.14.1"
    "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71" = "axios@0.30.4"
    "07d889e2dadce6f3910dcbc253317d28ca61c766" = "plain-crypto-js@4.2.1"
}
$hashHit = $false
$npmCache = "$env:APPDATA\npm-cache"
if (Test-Path $npmCache) {
    $cachedFiles = Get-ChildItem -Path $npmCache -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 100
    foreach ($file in $cachedFiles) {
        $hash = (Get-FileHash $file.FullName -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
        if ($hash -and $maliciousHashes.ContainsKey($hash.ToLower())) {
            Write-Host "[!] MALICIOUS HASH FOUND: $($file.FullName) matches $($maliciousHashes[$hash.ToLower()])" -ForegroundColor Red
            $findings += "Malicious hash match: $($file.FullName)"
            $compromised = $true
            $hashHit = $true
        }
    }
}
if (-not $hashHit) {
    Write-Host "[+] No malicious hashes found in npm cache" -ForegroundColor Green
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
    Write-Host "  2. Block C2: sfrclak.com and 142.11.206.73 port 8000" -ForegroundColor Yellow
    Write-Host "  3. Do NOT clean in place - rebuild from known-good backup" -ForegroundColor Yellow
    Write-Host "  4. Rotate ALL credentials: npm tokens, AWS/Azure/GCP keys, SSH keys, .env values" -ForegroundColor Yellow
    Write-Host "  5. Review cloud and CI/CD access logs for unauthorized activity" -ForegroundColor Yellow
    Write-Host "  6. Report to your security team immediately" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "  You're clean, jelly bean." -ForegroundColor Green
    Write-Host ""
    Write-Host "  No IOCs found on this system." -ForegroundColor Green
    Write-Host "  Safe axios versions: 1.14.0 (1.x) or 0.30.3 (0.x)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Recommended hardening:" -ForegroundColor Yellow
    Write-Host "  - Pin axios version explicitly in package.json" -ForegroundColor Yellow
    Write-Host "  - Block C2 at firewall: sfrclak.com and 142.11.206.73 port 8000" -ForegroundColor Yellow
    Write-Host "  - Run: npm install --ignore-scripts in CI environments" -ForegroundColor Yellow
    Write-Host "  - Enable npm provenance checking for critical packages" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Source: https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan"
Write-Host "Scripts: https://github.com/gib-sea/ioc-checkers"
Write-Host ""

#!/bin/bash
# ============================================================
# Axios npm Supply Chain Compromise - IOC Checker
# CVE: Axios 1.14.1 / 0.30.4 - March 31, 2026
# Checks for RAT artifacts dropped by malicious postinstall
# For Linux and macOS
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

COMPROMISED=0
FINDINGS=()

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Axios Supply Chain Compromise - IOC Check${NC}"
echo -e "${CYAN}  March 31, 2026 | axios 1.14.1 / 0.30.4  ${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Detect OS
OS="$(uname -s)"

# Check 1: Platform-specific RAT artifact
echo -e "${YELLOW}[*] Checking for RAT artifact...${NC}"

if [ "$OS" = "Darwin" ]; then
    RAT_PATH="/Library/Caches/com.apple.act.mond"
    if [ -f "$RAT_PATH" ]; then
        echo -e "${RED}[!] FOUND macOS RAT artifact: $RAT_PATH${NC}"
        FINDINGS+=("macOS RAT artifact found at $RAT_PATH")
        COMPROMISED=1
    else
        echo -e "${GREEN}[+] macOS RAT artifact not found${NC}"
    fi
elif [ "$OS" = "Linux" ]; then
    RAT_PATH="/tmp/ld.py"
    if [ -f "$RAT_PATH" ]; then
        echo -e "${RED}[!] FOUND Linux RAT artifact: $RAT_PATH${NC}"
        FINDINGS+=("Linux RAT artifact found at $RAT_PATH")
        COMPROMISED=1
    else
        echo -e "${GREEN}[+] Linux RAT artifact not found${NC}"
    fi
fi

# Check 2: plain-crypto-js in node_modules
echo ""
echo -e "${YELLOW}[*] Scanning for plain-crypto-js in node_modules...${NC}"

PLAIN_CRYPTO=$(find "$HOME" /usr/local/lib /usr/lib -name "plain-crypto-js" -type d 2>/dev/null | head -10)

if [ -n "$PLAIN_CRYPTO" ]; then
    while IFS= read -r location; do
        echo -e "${RED}[!] FOUND: $location${NC}"
        FINDINGS+=("plain-crypto-js found at $location")
        COMPROMISED=1
    done <<< "$PLAIN_CRYPTO"
else
    echo -e "${GREEN}[+] plain-crypto-js not found${NC}"
fi

# Check 3: Compromised axios versions in lockfiles
echo ""
echo -e "${YELLOW}[*] Scanning for compromised axios versions in lockfiles...${NC}"

LOCKFILES=$(find "$HOME" -name "package-lock.json" 2>/dev/null | head -20)
AXIOS_HIT=0

if [ -n "$LOCKFILES" ]; then
    while IFS= read -r lockfile; do
        if grep -q '"axios": "1\.14\.1"\|"axios": "0\.30\.4"' "$lockfile" 2>/dev/null; then
            echo -e "${RED}[!] FOUND compromised axios version in: $lockfile${NC}"
            FINDINGS+=("Compromised axios version in $lockfile")
            COMPROMISED=1
            AXIOS_HIT=1
        fi
    done <<< "$LOCKFILES"
fi

if [ $AXIOS_HIT -eq 0 ]; then
    echo -e "${GREEN}[+] No compromised axios versions found in lockfiles${NC}"
fi

# Check 4: Network connections to C2
echo ""
echo -e "${YELLOW}[*] Checking for connections to known C2 (sfrclak.com)...${NC}"

if netstat -an 2>/dev/null | grep -q "sfrclak" || ss -an 2>/dev/null | grep -q "sfrclak"; then
    echo -e "${RED}[!] ACTIVE C2 CONNECTION DETECTED${NC}"
    FINDINGS+=("Active connection to C2 domain detected")
    COMPROMISED=1
else
    echo -e "${GREEN}[+] No active C2 connections detected${NC}"
fi

# Final verdict
echo ""
echo -e "${CYAN}============================================${NC}"

if [ $COMPROMISED -eq 1 ]; then
    echo ""
    echo -e "${RED}  *** YOU'VE BEEN PWNED ***${NC}"
    echo ""
    echo -e "${RED}  Indicators of compromise found:${NC}"
    for finding in "${FINDINGS[@]}"; do
        echo -e "${RED}  - $finding${NC}"
    done
    echo ""
    echo -e "${YELLOW}  IMMEDIATE ACTIONS:${NC}"
    echo -e "${YELLOW}  1. Isolate this machine from the network NOW${NC}"
    echo -e "${YELLOW}  2. Do NOT attempt to clean in place - rebuild from known-good backup${NC}"
    echo -e "${YELLOW}  3. Rotate ALL credentials: npm tokens, AWS keys, SSH keys, cloud creds, .env values${NC}"
    echo -e "${YELLOW}  4. Review cloud access logs for unauthorized activity${NC}"
    echo -e "${YELLOW}  5. Report to your security team immediately${NC}"
    echo ""
else
    echo ""
    echo -e "${GREEN}  You're clean, jelly bean.${NC}"
    echo ""
    echo -e "${GREEN}  No IOCs found on this system.${NC}"
    echo -e "${GREEN}  Safe axios versions: 1.14.0 (1.x) or 0.30.3 (0.x)${NC}"
    echo ""
    echo -e "${YELLOW}  Still recommended:${NC}"
    echo -e "${YELLOW}  - Pin your axios version explicitly in package.json${NC}"
    echo -e "${YELLOW}  - Run: npm install --ignore-scripts in CI environments${NC}"
    echo -e "${YELLOW}  - Enable npm provenance checking for critical packages${NC}"
    echo ""
fi

echo -e "${CYAN}============================================${NC}"
echo ""
echo "More info: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan"
echo ""

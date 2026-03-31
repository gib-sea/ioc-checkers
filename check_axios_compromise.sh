#!/bin/bash
# ============================================================
# Axios npm Supply Chain Compromise - IOC Checker
# Axios 1.14.1 / 0.30.4 - March 31, 2026
# Source: SANS Internet Storm Center / StepSecurity
# github.com/gib-sea/ioc-checkers
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

OS="$(uname -s)"

# Check 1: Platform-specific RAT artifact
echo -e "${YELLOW}[*] Checking for RAT artifacts...${NC}"

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

# Check 2: Shell profile persistence (macOS and Linux)
echo ""
echo -e "${YELLOW}[*] Checking shell profiles for unauthorized modifications...${NC}"

PROFILE_FILES=("$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.profile")
PROFILE_HIT=0
for profile in "${PROFILE_FILES[@]}"; do
    if [ -f "$profile" ]; then
        if grep -q "sfrclak\|plain-crypto-js\|wt\.exe\|ld\.py\|com\.apple\.act" "$profile" 2>/dev/null; then
            echo -e "${RED}[!] SUSPICIOUS ENTRY FOUND in $profile${NC}"
            FINDINGS+=("Suspicious entry in shell profile: $profile")
            COMPROMISED=1
            PROFILE_HIT=1
        fi
    fi
done
if [ $PROFILE_HIT -eq 0 ]; then
    echo -e "${GREEN}[+] No suspicious entries found in shell profiles${NC}"
fi

# Check 3: plain-crypto-js in node_modules
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

# Check 4: Compromised axios versions in lockfiles
echo ""
echo -e "${YELLOW}[*] Scanning for compromised axios versions in lockfiles...${NC}"

LOCKFILES=$(find "$HOME" -name "package-lock.json" -o -name "yarn.lock" 2>/dev/null | head -20)
AXIOS_HIT=0

if [ -n "$LOCKFILES" ]; then
    while IFS= read -r lockfile; do
        if grep -q '"axios": "1\.14\.1"\|"axios": "0\.30\.4"\|axios@1\.14\.1\|axios@0\.30\.4' "$lockfile" 2>/dev/null; then
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

# Check 5: Network connections to C2
echo ""
echo -e "${YELLOW}[*] Checking for connections to known C2 (sfrclak.com / 142.11.206.73)...${NC}"

if netstat -an 2>/dev/null | grep -q "sfrclak\|142\.11\.206\.73" || ss -an 2>/dev/null | grep -q "sfrclak\|142\.11\.206\.73"; then
    echo -e "${RED}[!] ACTIVE C2 CONNECTION DETECTED${NC}"
    FINDINGS+=("Active connection to C2 detected")
    COMPROMISED=1
else
    echo -e "${GREEN}[+] No active C2 connections detected${NC}"
fi

# Check 6: Known malicious file hashes
echo ""
echo -e "${YELLOW}[*] Checking for known malicious file hashes...${NC}"

MALICIOUS_HASHES=(
    "2553649f232204966871cea80a5d0d6adc700ca:axios@1.14.1"
    "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71:axios@0.30.4"
    "07d889e2dadce6f3910dcbc253317d28ca61c766:plain-crypto-js@4.2.1"
)

HASH_HIT=0
NPM_CACHE="$HOME/.npm"
if [ -d "$NPM_CACHE" ]; then
    while IFS= read -r filepath; do
        FILEHASH=$(sha1sum "$filepath" 2>/dev/null | cut -d' ' -f1)
        for entry in "${MALICIOUS_HASHES[@]}"; do
            HASH="${entry%%:*}"
            LABEL="${entry##*:}"
            if [ "$FILEHASH" = "$HASH" ]; then
                echo -e "${RED}[!] MALICIOUS HASH FOUND: $filepath matches $LABEL${NC}"
                FINDINGS+=("Malicious hash match: $filepath ($LABEL)")
                COMPROMISED=1
                HASH_HIT=1
            fi
        done
    done < <(find "$NPM_CACHE" -type f 2>/dev/null | head -200)
fi

if [ $HASH_HIT -eq 0 ]; then
    echo -e "${GREEN}[+] No malicious hashes found in npm cache${NC}"
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
    echo -e "${YELLOW}  2. Block C2: sfrclak.com and 142.11.206.73 port 8000${NC}"
    echo -e "${YELLOW}  3. Do NOT clean in place - rebuild from known-good backup${NC}"
    echo -e "${YELLOW}  4. Rotate ALL credentials: npm tokens, AWS/Azure/GCP keys, SSH keys, .env values${NC}"
    echo -e "${YELLOW}  5. Review cloud and CI/CD access logs for unauthorized activity${NC}"
    echo -e "${YELLOW}  6. Report to your security team immediately${NC}"
    echo ""
else
    echo ""
    echo -e "${GREEN}  You're clean, jelly bean.${NC}"
    echo ""
    echo -e "${GREEN}  No IOCs found on this system.${NC}"
    echo -e "${GREEN}  Safe axios versions: 1.14.0 (1.x) or 0.30.3 (0.x)${NC}"
    echo ""
    echo -e "${YELLOW}  Recommended hardening:${NC}"
    echo -e "${YELLOW}  - Pin axios version explicitly in package.json${NC}"
    echo -e "${YELLOW}  - Block C2 at firewall: sfrclak.com and 142.11.206.73 port 8000${NC}"
    echo -e "${YELLOW}  - Run: npm install --ignore-scripts in CI environments${NC}"
    echo -e "${YELLOW}  - Enable npm provenance checking for critical packages${NC}"
    echo ""
fi

echo -e "${CYAN}============================================${NC}"
echo ""
echo "Source: https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan"
echo "Scripts: https://github.com/gib-sea/ioc-checkers"
echo ""

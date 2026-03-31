# ioc-checkers

Quick IOC detection scripts for active security incidents.

Built for IT professionals and security teams who need fast, no-frills checks without waiting for vendor tooling to catch up.

---

## Axios npm Supply Chain Compromise - March 31, 2026

Axios versions **1.14.1** and **0.30.4** were backdoored in a supply chain attack.
An attacker compromised the npm account of the primary Axios maintainer and published malicious versions containing a hidden dependency (`plain-crypto-js`) that silently dropped a cross-platform Remote Access Trojan.

Any system that ran `npm install` between approximately **00:21 and 03:15 UTC on March 31, 2026** should be considered compromised.

Safe versions: `axios@1.14.0` (1.x users) or `axios@0.30.3` (0.x users)

---

### What the scripts check

- Platform-specific RAT artifacts
  - Windows: `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Linux: `/tmp/ld.py`
- Shell profile files for persistence (`~/.bashrc`, `~/.zshrc`, `~/.bash_profile`)
- Presence of `plain-crypto-js` in node_modules
- Compromised axios versions in `package-lock.json` and `yarn.lock` files
- Active network connections to known C2: `sfrclak.com` / `142.11.206.73` port 8000
- Known malicious file hashes (SHA1) in npm cache

### Known malicious hashes

| Package | SHA1 |
|---|---|
| axios@1.14.1 | `2553649f232204966871cea80a5d0d6adc700ca` |
| axios@0.30.4 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js@4.2.1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |

---

### Usage

**Windows (PowerShell - run as Administrator):**
```powershell
.\Check-AxiosCompromise.ps1
```

**Linux / macOS (Bash):**
```bash
chmod +x check_axios_compromise.sh
./check_axios_compromise.sh
```

Output is either `YOU'VE BEEN PWNED` with findings and immediate action steps, or `You're clean, jelly bean.` with hardening recommendations.

---

### If you find IOCs

1. Isolate the machine from the network immediately
2. Block C2 at your firewall: `sfrclak.com` and `142.11.206.73` port 8000
3. Do not attempt to clean in place - rebuild from a known-good backup taken before March 30, 2026
4. Rotate all credentials: npm tokens, AWS/Azure/GCP keys, SSH keys, database credentials, CI/CD secrets, and any values in .env files
5. Review cloud and code repository access logs for unauthorized activity
6. Check CI/CD runners and build infrastructure - not just developer workstations
7. Report to your security team

---

### References

- [SANS - Axios npm Supply Chain Compromise](https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan)
- [StepSecurity - Axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Help Net Security - Axios npm packages backdoored](https://www.helpnetsecurity.com/2026/03/31/axios-npm-backdoored-supply-chain-attack/)

---

### Disclaimer

These scripts are provided as-is for informational and detection purposes. They are not a substitute for professional incident response. If you find indicators of compromise, engage your security team and follow your organization's incident response procedures.

---

*Scripts by Sean Gibson | github.com/gib-sea*  
*CompTIA Security+ | Pursuing CySA+ and SC-200*

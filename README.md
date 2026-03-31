# ioc-checkers

Quick IOC detection scripts for active security incidents.

Built for IT professionals and security teams who need fast, no-frills checks.

---

## Axios npm Supply Chain Compromise - March 31, 2026

Axios versions **1.14.1** and **0.30.4** were backdoored in a supply chain attack.
An attacker compromised the npm account of the primary Axios maintainer and published malicious versions containing a hidden dependency (`plain-crypto-js`) that silently dropped a cross-platform Remote Access Trojan.

Any system that ran `npm install` between approximately **00:21 and 03:15 UTC on March 31, 2026** should be considered compromised.

Safe versions: `axios@1.14.0` (1.x users) or `axios@0.30.3` (0.x users)

---

### What the scripts check

- Platform-specific RAT artifact
  - Windows: `%PROGRAMDATA%\wt.exe`
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Linux: `/tmp/ld.py`
- Presence of `plain-crypto-js` in node_modules
- Compromised axios versions in package-lock.json files
- Active network connections to known C2 domain `sfrclak.com`

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
2. Do not attempt to clean in place - rebuild from a known-good backup taken before March 30, 2026
3. Rotate all credentials accessible from the compromised machine - npm tokens, AWS keys, SSH keys, cloud credentials, and any values in .env files
4. Review cloud and code repository access logs for unauthorized activity
5. Report to your security team

---

### References

- [StepSecurity - Axios Compromised on npm](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Help Net Security - Axios npm packages backdoored](https://www.helpnetsecurity.com/2026/03/31/axios-npm-backdoored-supply-chain-attack/)
- [The Hacker News - Axios Supply Chain Attack](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)

---

### Disclaimer

These scripts are provided as-is for informational and detection purposes. They are not a substitute for professional incident response. If you find indicators of compromise, engage your security team and follow your organization's incident response procedures.

---

*Scripts by Sean Gibson | github.com/gib-sea*
*CompTIA Security+ | Pursuing CySA+ and SC-200*

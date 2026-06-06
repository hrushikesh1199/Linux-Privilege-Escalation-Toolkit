# 🔐 Linux Privilege Escalation Automation Toolkit

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Bash](https://img.shields.io/badge/Bash-5.0%2B-green?style=for-the-badge&logo=gnu-bash)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)
![Security](https://img.shields.io/badge/Security-Red%20%7C%20Blue%20Team-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**An automated Linux security auditing toolkit for detecting privilege escalation vectors.**  
Built for authorized penetration testing and defensive security auditing.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-scanning-modules) • [Report](#-sample-output) • [References](#-references)

</div>

---

## ⚠️ Legal Disclaimer

> **This toolkit is intended STRICTLY for:**
> - Educational purposes
> - Authorized penetration testing (with written permission)
> - Defensive security auditing on systems you own
>
> **Running this tool without explicit written authorization is ILLEGAL.**  
> The author assumes **zero liability** for any unauthorized use.

---

## 📌 Overview

The **Linux PrivEsc Automation Toolkit** is a professional-grade security auditing tool that automates the detection of privilege escalation vulnerabilities on Linux systems.

It reflects real-world **Red Team enumeration** and **Blue Team auditing** techniques used by security engineers in penetration testing and SOC operations.

### What it does
- Scans for **SUID/SGID binaries** and matches them against [GTFOBins](https://gtfobins.github.io)
- Identifies **misconfigured file permissions** on sensitive files
- Detects **vulnerable cron jobs** (writable scripts, wildcard injection, PATH hijack)
- Audits **systemd services** for misconfigurations
- Matches **kernel version** against a database of known CVEs
- Generates structured **TXT + JSON security reports**

---

## 🗂️ Project Structure

```
linux-privesc-toolkit/
│
├── privesc_toolkit.py          # Main entry point
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── modules/                    # Core scanning modules
│   ├── __init__.py
│   ├── banner.py               # Colors, display utilities
│   ├── system_info.py          # System info collection
│   ├── suid_scanner.py         # SUID/SGID + GTFOBins matching
│   ├── permissions.py          # File permission analysis
│   ├── services.py             # Service misconfiguration scanner
│   ├── cron_scanner.py         # Cron job vulnerability analysis
│   ├── kernel_cve.py           # Kernel CVE matching
│   └── report_generator.py     # TXT + JSON report export
│
├── scripts/
│   ├── quick_scan.sh           # Bash rapid enumeration script
│   └── setup.sh                # Installation & setup script
│
├── reports/                    # Generated reports (gitignored)
│   └── .gitkeep
│
├── docs/
│   └── detailed_report.md      # Full project documentation
│
└── tests/
    └── test_modules.py         # Unit tests
```

---

## ✅ Features

| Module | Description | Severity Detection |
|--------|-------------|-------------------|
| 🖥️ System Info | OS, kernel, user, PATH, environment | HIGH |
| 🔑 SUID/SGID | 50+ GTFOBins-matched exploitable binaries | CRITICAL |
| 📂 Permissions | /etc/passwd, /etc/shadow, world-writable | CRITICAL |
| ⚙️ Services | Systemd misconfigurations, sudo rules | CRITICAL |
| ⏰ Cron Jobs | Writable scripts, wildcard injection | CRITICAL |
| 💀 Kernel CVEs | 15+ known CVE checks (Dirty Cow, Dirty Pipe…) | CRITICAL |
| 📊 Reports | Structured TXT and JSON export | — |

---

## 🛠️ Installation

### Prerequisites

```bash
# Required
sudo apt update && sudo apt install python3 python3-pip -y

# Recommended tools (for complete scan coverage)
sudo apt install binutils libcap2-bin net-tools -y
```

### Clone and Setup

```bash
# Clone the repository
git clone https://github.com/hrushikesh1199/linux-privesc-toolkit.git
cd linux-privesc-toolkit

# Run setup script
chmod +x scripts/setup.sh
bash scripts/setup.sh

# Install Python dependencies
pip3 install -r requirements.txt
```

---

## 🚀 Usage

### Full Scan (Recommended: run as root for complete results)

```bash
sudo python3 privesc_toolkit.py
```

### Scan a Specific Module

```bash
# SUID binary scan only
sudo python3 privesc_toolkit.py --module suid

# Cron job analysis only
sudo python3 privesc_toolkit.py --module cron

# Kernel CVE check only
sudo python3 privesc_toolkit.py --module kernel

# File permission audit only
sudo python3 privesc_toolkit.py --module perms

# Service misconfiguration scan
sudo python3 privesc_toolkit.py --module services

# System information
sudo python3 privesc_toolkit.py --module sysinfo
```

### Export Reports

```bash
# Export both TXT and JSON (default)
sudo python3 privesc_toolkit.py --output reports/my_audit

# Export JSON only
sudo python3 privesc_toolkit.py --format json --output /tmp/audit

# Quiet mode (suppress progress, just save report)
sudo python3 privesc_toolkit.py --quiet --output reports/silent_scan
```

### Bash Quick Scan

```bash
# Fast bash-based enumeration (no Python needed)
sudo bash scripts/quick_scan.sh

# Save output
sudo bash scripts/quick_scan.sh | tee /tmp/quick_audit.txt
```

### All Options

```
usage: privesc_toolkit.py [-h] [--module MODULE] [--output PATH] [--format FORMAT] [--quiet] [--no-color] [--version]

options:
  --module   {sysinfo,suid,perms,services,cron,kernel}  Run single module
  --output   PATH    Output path for report (no extension)
  --format   {txt,json,both}   Report format (default: both)
  --quiet             Suppress banner and progress output
  --no-color          Disable colored output
  --version           Show version
```

---

## 🔍 Scanning Modules

### 1. System Information (`system_info.py`)
**Commands:** `uname -a`, `id`, `whoami`, `hostname`, `env`, `sudo -l`

Collects:
- Kernel version, OS distribution, architecture
- Current user, groups, home directory
- PATH analysis → detects **writable directories** (PATH hijacking)
- Dangerous environment variables (`LD_PRELOAD`, `PYTHONPATH`)
- Sudo privileges (`NOPASSWD` detection)

### 2. SUID/SGID Scanner (`suid_scanner.py`)
**Commands:** `find / -perm -4000`, `find / -perm -2000`, `getcap -r /`

- Scans entire filesystem for SUID/SGID binaries
- Matches against **50+ GTFOBins entries** with exploit commands
- Detects **Linux capabilities** (`cap_setuid`, `cap_net_admin`, etc.)
- Whitelist of standard SUID binaries to reduce false positives

**Example GTFOBins matches:** `vim`, `find`, `python3`, `perl`, `awk`, `nmap`, `tar`, `env`

### 3. File Permission Scanner (`permissions.py`)
**Commands:** `find / -writable`, `stat /etc/passwd`, `ls -la /home`

- Checks `/etc/passwd` (writable = add root user)
- Checks `/etc/shadow` (readable = crack hashes)
- Audits `/etc/sudoers`, `/etc/crontab`, SSH config
- Identifies world-writable files in system paths
- Scans home directory exposures

### 4. Service Scanner (`services.py`)
**Commands:** `systemctl`, `ps aux`, `sudo -l`

- Parses all `.service` files in `/etc/systemd/system/`
- Detects root services with **writable ExecStart binaries**
- Identifies relative paths → **PATH hijacking** in services
- Analyses sudo rules for dangerous patterns:
  - `NOPASSWD` for shells, editors, interpreters
  - `env_keep` for `LD_PRELOAD` (shared library injection)

### 5. Cron Job Scanner (`cron_scanner.py`)
**Commands:** `crontab -l`, `cat /etc/crontab`, `cat /etc/cron.d/*`

Attack vectors detected:
- **Writable scripts** executed by root cron
- **Relative paths** without absolute binary → PATH hijack
- **Wildcard injection** in `tar`, `chown`, `rsync`, `chmod`, `find`
- **Writable parent directories** of cron scripts

### 6. Kernel CVE Detection (`kernel_cve.py`)
**Commands:** `uname -r`, `uname -a`, `cat /proc/version`

Matches kernel version against **15+ known CVEs:**

| CVE | Name | Severity | Affected Versions |
|-----|------|----------|-------------------|
| CVE-2022-0847 | **Dirty Pipe** | CRITICAL | 5.8 – 5.16.11 |
| CVE-2016-5195 | **Dirty COW** | CRITICAL | 3.3 – 4.8.3 |
| CVE-2014-3153 | **Futex Requeue** | CRITICAL | 3.3 – 3.16 |
| CVE-2021-3156 | **Baron Samedit** | CRITICAL | sudo ≤ 1.9.5p1 |
| CVE-2015-1328 | **OverlayFS** | HIGH | 3.13 – 3.19.3 |
| CVE-2017-16995 | **eBPF Bug** | HIGH | 4.4 – 4.13 |
| CVE-2019-13272 | **PTRACE** | HIGH | 4.14 – 5.10 |
| CVE-2023-4147 | **Netfilter UAF** | CRITICAL | 4.0 – 6.5 |

---

## 📊 Sample Output

```
  ██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗
  ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝
  ██████╔╝██████╔╝██║██║   ██║█████╗  ███████╗██║
  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║██║
  ██║     ██║  ██║██║ ╚████╔╝ ███████╗███████║╚██████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝

  Linux Privilege Escalation Automation Toolkit v1.0

┌────────────────────────────────────────────────────────────┐
│  SUID/SGID Binaries                                        │
└────────────────────────────────────────────────────────────┘
  [*] Total SUID binaries found : 14
  ⚠  EXPLOITABLE SUID BINARIES (GTFOBins Match):
  [CRITICAL] /usr/bin/vim
           Exploit → vim -c ':!/bin/sh'
           Reference: https://gtfobins.github.io/gtfobins/vim/#suid

  [CRITICAL] /usr/bin/find
           Exploit → find . -exec /bin/sh -p \; -quit
           Reference: https://gtfobins.github.io/gtfobins/find/#suid

┌────────────────────────────────────────────────────────────┐
│  Kernel CVE Detection                                      │
└────────────────────────────────────────────────────────────┘
  [*] Kernel Version : 5.10.0-26-amd64
  [CRITICAL] CVE-2022-0847 – Dirty Pipe
           Affects kernel 5.8 – 5.16.11
           Reference: https://dirtypipe.cm4all.com

[+] Text report saved  → reports/privesc_report_20241201_143022.txt
[+] JSON report saved  → reports/privesc_report_20241201_143022.json
[*] Scan completed in 42s | Total findings: 28
```

---

## 🔵 Blue Team Mitigations

| Finding | Mitigation Command |
|---------|-------------------|
| Writable SUID binary | `chmod u-s /usr/bin/<binary>` |
| World-writable /etc/passwd | `chmod 644 /etc/passwd` |
| Readable /etc/shadow | `chmod 640 /etc/shadow && chown root:shadow /etc/shadow` |
| NOPASSWD sudo | Edit `/etc/sudoers` → remove `NOPASSWD` |
| Writable cron script | `chmod 700 /etc/cron.d/<script> && chown root:root` |
| Outdated kernel | `sudo apt update && sudo apt dist-upgrade` |
| LD_PRELOAD in sudo | Remove `env_keep+=LD_PRELOAD` from `/etc/sudoers` |

---

## 🧪 Running Tests

```bash
cd linux-privesc-toolkit
python3 -m pytest tests/ -v
```

---

## 📚 References & Resources

### Primary References
- 🔗 [GTFOBins](https://gtfobins.github.io) – Unix binary exploit paths
- 🔗 [HackTricks Linux PrivEsc](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) – Comprehensive guide
- 🔗 [LinPEAS](https://github.com/carlospolop/PEASS-ng) – Similar automated tool
- 🔗 [Linux Kernel CVEs](https://www.linuxkernelcves.com) – Kernel vulnerability database
- 🔗 [ExploitDB](https://www.exploit-db.com) – Exploit database
- 🔗 [NVD – NIST](https://nvd.nist.gov) – National Vulnerability Database
- 🔗 [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) – Hardening guides

### CVE References
- 🔗 [Dirty Pipe (CVE-2022-0847)](https://dirtypipe.cm4all.com)
- 🔗 [Dirty COW (CVE-2016-5195)](https://dirtycow.ninja)
- 🔗 [Baron Samedit (CVE-2021-3156)](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156)

---

## 👨‍💻 Author

**Hrushikesh Pawar**  
B.E. Electronics & Telecommunication | JSPM's JSCOE, Pune  
Cybersecurity Enthusiast | SOC Analyst | Web App Pentester

[![GitHub](https://img.shields.io/badge/GitHub-hrushikesh1199-black?style=flat&logo=github)](https://github.com/hrushikesh1199)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://linkedin.com/in/hrushikesh-chaudhari)

---

## 📄 License

MIT License – See [LICENSE](LICENSE) for details.

---

<div align="center">
⭐ Star this repo if it helped you learn!  
🔐 Use responsibly. Hack ethically.
</div>

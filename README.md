<div align="center">

<!-- Animated Header -->

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0c29,50:302b63,100:24243e&height=250&section=header&text=Linux%20Privilege%20Escalation%20Toolkit&fontSize=38&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Automated%20Linux%20Security%20Auditing%20%7C%20Privilege%20Escalation%20Detection&descAlignY=60&descSize=17" width="100%"/>

<br>

<a href="https://github.com/hrushikesh1199/linux-privesc-toolkit">
<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&duration=3000&pause=1000&color=8A2BE2&center=true&vCenter=true&width=800&lines=Automated+Linux+Security+Auditing;Privilege+Escalation+Detection;SUID%2FSGID+%7C+Cron+%7C+Sudo+%7C+Systemd;Kernel+CVE+Detection;Red+Team+Enumeration+%7C+Blue+Team+Hardening" alt="Typing SVG"/>
</a>

<br>

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge\&logo=python\&logoColor=white)](https://www.python.org/)
[![Bash](https://img.shields.io/badge/Bash-5.0%2B-4EAA25?style=for-the-badge\&logo=gnu-bash\&logoColor=white)](https://www.gnu.org/software/bash/)
[![Linux](https://img.shields.io/badge/Linux-Security-FCC624?style=for-the-badge\&logo=linux\&logoColor=black)](https://www.linux.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)](https://github.com/hrushikesh1199/linux-privesc-toolkit)

<br><br>

**An automated Linux security auditing toolkit for detecting privilege escalation vectors.**

Built for **authorized penetration testing, security research, and defensive Linux auditing.**

<br>

[![GitHub Stars](https://img.shields.io/github/stars/hrushikesh1199/linux-privesc-toolkit?style=flat-square\&logo=github)](https://github.com/hrushikesh1199/linux-privesc-toolkit/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/hrushikesh1199/linux-privesc-toolkit?style=flat-square\&logo=github)](https://github.com/hrushikesh1199/linux-privesc-toolkit/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/hrushikesh1199/linux-privesc-toolkit?style=flat-square\&logo=github)](https://github.com/hrushikesh1199/linux-privesc-toolkit/issues)

</div>

---

## ⚠️ Legal Disclaimer

> **This toolkit is intended STRICTLY for:**
>
> * 🎓 Educational purposes
> * 🛡️ Authorized penetration testing with written permission
> * 🔍 Defensive security auditing on systems you own
>
> **Running this tool against systems without explicit authorization may be illegal.**
>
> The author assumes zero liability for unauthorized or malicious use.

---

## 🎯 Overview

**Linux PrivEsc Automation Toolkit** is a security auditing framework designed to automate the discovery of common Linux privilege escalation vectors.

It combines **Red Team enumeration techniques** with **Blue Team security auditing** to identify dangerous configurations, vulnerable permissions, risky services, scheduled tasks, SUID/SGID binaries, Linux capabilities, and potentially vulnerable kernel versions.

### 🔎 What It Does

| Security Area       | Detection                                                      |
| ------------------- | -------------------------------------------------------------- |
| 🔑 SUID / SGID      | Finds privileged binaries and GTFOBins matches                 |
| 📂 File Permissions | Detects dangerous writable/readable system files               |
| ⏰ Cron Jobs         | Identifies writable scripts, PATH hijacking and wildcard risks |
| ⚙️ Systemd          | Audits privileged services and executable permissions          |
| 🔐 Sudo             | Identifies dangerous `sudo` and `NOPASSWD` configurations      |
| 🧠 Kernel           | Matches kernel versions against known CVEs                     |
| 🐧 System Info      | Collects OS, user, groups, PATH and environment information    |
| 📊 Reporting        | Generates structured TXT and JSON security reports             |

---

## ✨ Features

* 🔍 Automated Linux enumeration
* 🔑 SUID / SGID binary detection
* 🧩 GTFOBins-based binary matching
* 🛡️ Linux capability detection
* 📂 Dangerous file permission analysis
* ⏰ Cron security auditing
* ⚙️ Systemd service analysis
* 🔐 Sudo configuration auditing
* 🧠 Kernel CVE detection
* 🌐 PATH hijacking detection
* 💉 `LD_PRELOAD` / environment variable checks
* 📊 Automated TXT + JSON reporting
* 🐚 Bash quick-scan support
* 🧪 Unit testing support
* 🎨 Colored terminal output

---

## 🏗️ Architecture

```text
                         ┌──────────────────────┐
                         │   Linux System       │
                         └──────────┬───────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────┐
                    │    PrivEsc Toolkit          │
                    │     privesc_toolkit.py      │
                    └──────────────┬──────────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
             ▼                     ▼                     ▼
      ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
      │ System Info │       │ SUID / SGID │       │ Permissions │
      └─────────────┘       └─────────────┘       └─────────────┘
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
             ▼                     ▼                     ▼
      ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
      │   Systemd   │       │ Cron Jobs   │       │ Kernel CVEs │
      └─────────────┘       └─────────────┘       └─────────────┘
                                   │
                                   ▼
                         ┌─────────────────────┐
                         │ Security Findings   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ TXT + JSON Reports  │
                         └─────────────────────┘
```

---

## 🗂️ Project Structure

```text
linux-privesc-toolkit/
│
├── privesc_toolkit.py
├── requirements.txt
├── README.md
│
├── modules/
│   ├── __init__.py
│   ├── banner.py
│   ├── system_info.py
│   ├── suid_scanner.py
│   ├── permissions.py
│   ├── services.py
│   ├── cron_scanner.py
│   ├── kernel_cve.py
│   └── report_generator.py
│
├── scripts/
│   ├── quick_scan.sh
│   └── setup.sh
│
├── reports/
│   └── .gitkeep
│
├── docs/
│   └── detailed_report.md
│
└── tests/
    └── test_modules.py
```

---

# 🛠️ Installation

### Requirements

```bash
sudo apt update

sudo apt install python3 python3-pip -y

sudo apt install binutils libcap2-bin net-tools -y
```

### Clone Repository

```bash
git clone https://github.com/hrushikesh1199/linux-privesc-toolkit.git

cd linux-privesc-toolkit
```

### Setup

```bash
chmod +x scripts/setup.sh

bash scripts/setup.sh

pip3 install -r requirements.txt
```

---

# 🚀 Usage

## Full Security Scan

For maximum visibility, run with appropriate privileges on systems you are authorized to audit:

```bash
sudo python3 privesc_toolkit.py
```

---

## 🔍 Scan Individual Modules

### System Information

```bash
sudo python3 privesc_toolkit.py --module sysinfo
```

### SUID / SGID

```bash
sudo python3 privesc_toolkit.py --module suid
```

### File Permissions

```bash
sudo python3 privesc_toolkit.py --module perms
```

### Systemd Services

```bash
sudo python3 privesc_toolkit.py --module services
```

### Cron Jobs

```bash
sudo python3 privesc_toolkit.py --module cron
```

### Kernel CVEs

```bash
sudo python3 privesc_toolkit.py --module kernel
```

---

# 📊 Report Generation

### TXT + JSON

```bash
sudo python3 privesc_toolkit.py \
  --output reports/my_audit
```

### JSON Only

```bash
sudo python3 privesc_toolkit.py \
  --format json \
  --output /tmp/audit
```

### Quiet Mode

```bash
sudo python3 privesc_toolkit.py \
  --quiet \
  --output reports/silent_scan
```

---

# 🐚 Bash Quick Scan

For lightweight enumeration:

```bash
sudo bash scripts/quick_scan.sh
```

Save results:

```bash
sudo bash scripts/quick_scan.sh | tee /tmp/quick_audit.txt
```

---

# ⚙️ Command Options

```text
usage: privesc_toolkit.py [-h]
                          [--module MODULE]
                          [--output PATH]
                          [--format FORMAT]
                          [--quiet]
                          [--no-color]
                          [--version]

options:

  --module
        {sysinfo,suid,perms,services,cron,kernel}

  --output
        PATH

  --format
        {txt,json,both}

  --quiet
        Suppress banner and progress output

  --no-color
        Disable colored output

  --version
        Show version
```

---

# 🔬 Scanning Modules

## 1️⃣ System Information

**Module:** `system_info.py`

Collects:

* Kernel version
* Operating system
* Architecture
* Current user
* Groups
* Hostname
* Home directory
* PATH configuration
* Writable PATH directories
* Dangerous environment variables
* `LD_PRELOAD`
* `PYTHONPATH`
* Sudo privileges
* `NOPASSWD` rules

---

## 2️⃣ SUID / SGID Scanner

**Module:** `suid_scanner.py`

Checks:

```bash
find / -perm -4000
find / -perm -2000
getcap -r /
```

Detects:

* SUID binaries
* SGID binaries
* Linux capabilities
* Potentially dangerous privileged binaries
* GTFOBins matches

Example binaries include:

```text
vim
find
python3
perl
awk
nmap
tar
env
```

---

## 3️⃣ File Permission Scanner

**Module:** `permissions.py`

Audits:

```text
/etc/passwd
/etc/shadow
/etc/sudoers
/etc/crontab
SSH configuration
System directories
Home directories
World-writable files
```

The scanner identifies dangerous permission configurations that could contribute to privilege escalation.

---

## 4️⃣ Systemd Service Scanner

**Module:** `services.py`

Analyzes:

```bash
systemctl
ps aux
sudo -l
```

Checks for:

* Root services
* Writable service executables
* Writable service directories
* Relative executable paths
* PATH hijacking opportunities
* Dangerous sudo configurations
* `LD_PRELOAD` related configurations

---

## 5️⃣ Cron Job Scanner

**Module:** `cron_scanner.py`

Analyzes:

```bash
crontab -l
cat /etc/crontab
cat /etc/cron.d/*
```

Checks for:

* Writable root cron scripts
* Relative executable paths
* Writable parent directories
* Unsafe wildcard usage
* PATH hijacking conditions

---

## 6️⃣ Kernel CVE Detection

**Module:** `kernel_cve.py`

Collects:

```bash
uname -r
uname -a
cat /proc/version
```

The toolkit compares detected kernel information against a database of known vulnerabilities.

Example CVEs included:

| CVE            | Vulnerability | Severity |
| -------------- | ------------- | -------- |
| CVE-2022-0847  | Dirty Pipe    | CRITICAL |
| CVE-2016-5195  | Dirty COW     | CRITICAL |
| CVE-2014-3153  | Futex Requeue | CRITICAL |
| CVE-2021-3156  | Baron Samedit | CRITICAL |
| CVE-2015-1328  | OverlayFS     | HIGH     |
| CVE-2017-16995 | eBPF Bug      | HIGH     |
| CVE-2019-13272 | PTRACE        | HIGH     |
| CVE-2023-4147  | Netfilter UAF | CRITICAL |

---

# 🖥️ Sample Output

```text
██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗
██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝
██████╔╝██████╔╝██║██║   ██║█████╗  ███████╗██║
██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║██║
██║     ██║  ██║██║ ╚████╔╝ ███████╗███████║╚██████╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝

Linux Privilege Escalation Automation Toolkit v1.0

┌────────────────────────────────────────────────────────────┐
│ SUID/SGID Binaries                                         │
└────────────────────────────────────────────────────────────┘

[*] Total SUID binaries found : 14

[CRITICAL] Potentially dangerous SUID binary detected

[+] Text report saved
[+] JSON report saved

[*] Scan completed
```

---

# 🛡️ Blue Team Mitigations

| Finding                         | Recommended Action                               |
| ------------------------------- | ------------------------------------------------ |
| Writable SUID binary            | Remove unnecessary SUID permissions              |
| Writable `/etc/passwd`          | Restore secure ownership and permissions         |
| Readable `/etc/shadow`          | Restrict access to privileged accounts           |
| Dangerous NOPASSWD sudo         | Review and restrict sudo rules                   |
| Writable cron script            | Restrict ownership and permissions               |
| Outdated kernel                 | Apply security updates                           |
| Unsafe service executable       | Restrict service file and executable permissions |
| Dangerous environment variables | Review sudo environment configuration            |

---

# 🧪 Testing

Run the test suite:

```bash
cd linux-privesc-toolkit

python3 -m pytest tests/ -v
```

---

# 📚 References

* [GTFOBins](https://gtfobins.github.io/) — Unix binary security reference
* [HackTricks Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
* [PEASS-ng / LinPEAS](https://github.com/peass-ng/PEASS-ng)
* [Linux Kernel CVEs](https://www.linuxkernelcves.com/)
* [Exploit Database](https://www.exploit-db.com/)
* [NVD](https://nvd.nist.gov/)
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

---

# 🎯 Security Recommendations

For defenders:

* Remove unnecessary SUID / SGID permissions
* Restrict writable system files
* Audit cron jobs regularly
* Review sudo privileges
* Harden systemd services
* Restrict dangerous environment variables
* Keep Linux kernels patched
* Monitor privileged service configurations
* Apply least-privilege principles
* Regularly perform security audits

---

# 👨‍💻 Author

<div align="center">

### Hrushikesh Pawar

**B.E. Electronics & Telecommunication Engineering**
JSPM's Jaywantrao Sawant College of Engineering, Pune

**Cybersecurity Enthusiast | SOC Analyst | Web Application Pentester**

<br>

<a href="https://github.com/hrushikesh1199">
<img src="https://img.shields.io/badge/GitHub-hrushikesh1199-181717?style=for-the-badge&logo=github&logoColor=white"/>
</a>

<a href="https://www.linkedin.com/in/hrushikesh20/">
<img src="https://img.shields.io/badge/LinkedIn-Hrushikesh%20Pawar-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white"/>
</a>

</div>

---

# 📄 License

This project is licensed under the **MIT License**.

See [LICENSE](LICENSE) for details.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:24243e,50:302b63,100:0f0c29&height=120&section=footer" width="100%"/>

### ⭐ Star this repository if it helped you learn!

**🔐 Use responsibly. Hack ethically.**

<br>

`Built for Security Research • Authorized Pentesting • Defensive Auditing`

</div>

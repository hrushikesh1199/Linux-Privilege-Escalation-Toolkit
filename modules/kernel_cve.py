"""
Module: Kernel CVE Detection
Identifies kernel version and matches against known privilege escalation CVEs.

Commands used:
  uname -r          → Kernel release version
  uname -a          → Full kernel info
  cat /proc/version → Kernel compilation details
  lsb_release -a    → Distribution info

References:
  CVE Database   : https://cve.mitre.org
  NVD            : https://nvd.nist.gov
  ExploitDB      : https://www.exploit-db.com
  Linux CVEs     : https://www.linuxkernelcves.com
"""

import subprocess
import re
from modules.banner import Colors, ok, warn, info, finding

# Known privilege escalation CVEs with kernel version ranges
# Format: (min_version_tuple, max_version_tuple, CVE_ID, name, description, exploitdb_link)
KERNEL_CVES = [
    (
        (2, 6, 22), (3, 9, 0),
        'CVE-2012-0056',
        'Mempodipper',
        'Local privilege escalation via /proc/PID/mem write.',
        'https://www.exploit-db.com/exploits/18411',
        'HIGH'
    ),
    (
        (3, 4, 0), (3, 14, 5),
        'CVE-2014-4699',
        'ptrace-SYSEMU',
        'ptrace() SYSEMU local privilege escalation.',
        'https://www.exploit-db.com/exploits/34134',
        'HIGH'
    ),
    (
        (3, 3, 0), (3, 16, 0),
        'CVE-2014-3153',
        'Futex requeue',
        'Privilege escalation via futex() requeue. Used in Towelroot.',
        'https://www.exploit-db.com/exploits/35370',
        'CRITICAL'
    ),
    (
        (3, 13, 0), (3, 19, 3),
        'CVE-2015-1328',
        'OverlayFS',
        'OverlayFS local privilege escalation (Ubuntu-specific).',
        'https://www.exploit-db.com/exploits/37292',
        'HIGH'
    ),
    (
        (3, 3, 0), (4, 8, 3),
        'CVE-2016-5195',
        'Dirty COW',
        'Race condition in copy-on-write. Most exploited Linux kernel bug ever.',
        'https://dirtycow.ninja | https://www.exploit-db.com/exploits/40611',
        'CRITICAL'
    ),
    (
        (4, 4, 0), (4, 13, 0),
        'CVE-2017-16995',
        'eBPF ld_abs/ld_ind',
        'eBPF verifier bug → arbitrary read/write → root.',
        'https://www.exploit-db.com/exploits/45010',
        'HIGH'
    ),
    (
        (4, 8, 0), (4, 16, 13),
        'CVE-2017-1000112',
        'UFO Scatterlist',
        'Memory corruption in UFO scatterlist. LPE to root.',
        'https://www.exploit-db.com/exploits/45010',
        'HIGH'
    ),
    (
        (4, 14, 0), (5, 10, 0),
        'CVE-2019-13272',
        'PTRACE_TRACEME',
        'Rogue parent process via PTRACE_TRACEME can gain root.',
        'https://www.exploit-db.com/exploits/47133',
        'HIGH'
    ),
    (
        (4, 10, 0), (5, 1, 17),
        'CVE-2019-16995',
        'rtnetlink Null Deref',
        'Kernel null dereference can lead to LPE.',
        'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16995',
        'MEDIUM'
    ),
    (
        (5, 0, 0), (5, 8, 0),
        'CVE-2020-8835',
        'eBPF ALU32',
        'eBPF verifier flaw in ALU32 operations → root. (Conf: 64-bit only)',
        'https://www.zerodayinitiative.com/advisories/ZDI-20-520/',
        'HIGH'
    ),
    (
        (5, 4, 0), (5, 10, 9),
        'CVE-2021-3156',
        'Baron Samedit (sudo)',
        'Sudo heap overflow → root. NOT kernel but critical system-level.',
        'https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156',
        'CRITICAL'
    ),
    (
        (5, 8, 0), (5, 16, 11),
        'CVE-2022-0847',
        'Dirty Pipe',
        'Overwrite arbitrary read-only files via pipe. LPE to root.',
        'https://dirtypipe.cm4all.com | https://www.exploit-db.com/exploits/50808',
        'CRITICAL'
    ),
    (
        (5, 15, 0), (6, 2, 0),
        'CVE-2023-0179',
        'Netfilter Netlink',
        'Heap buffer overflow in Netfilter Netlink. LPE.',
        'https://nvd.nist.gov/vuln/detail/CVE-2023-0179',
        'HIGH'
    ),
    (
        (6, 1, 0), (6, 3, 0),
        'CVE-2023-2598',
        'io_uring Fixed Table',
        'io_uring fixed file table UAF → privilege escalation.',
        'https://nvd.nist.gov/vuln/detail/CVE-2023-2598',
        'HIGH'
    ),
    (
        (4, 0, 0), (6, 5, 0),
        'CVE-2023-4147',
        'Netfilter nft_dynset',
        'Netfilter nf_tables use-after-free → root. Actively exploited.',
        'https://nvd.nist.gov/vuln/detail/CVE-2023-4147',
        'CRITICAL'
    ),
]


def parse_kernel_version(ver_string):
    """Parse kernel version string into a comparable tuple."""
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', ver_string)
    if match:
        return tuple(int(x) for x in match.groups())
    # Try 2-part version
    match2 = re.search(r'(\d+)\.(\d+)', ver_string)
    if match2:
        return (int(match2.group(1)), int(match2.group(2)), 0)
    return (0, 0, 0)


class KernelCVEScanner:
    def __init__(self):
        self.findings = {}

    def _run(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except Exception:
            return ""

    def scan(self):
        data = {
            'kernel_version'    : '',
            'kernel_full'       : '',
            'kernel_tuple'      : (0, 0, 0),
            'os_info'           : '',
            'vulnerable_cves'   : [],
            'critical_count'    : 0,
            'high_count'        : 0,
        }

        data['kernel_version'] = self._run("uname -r")
        data['kernel_full']    = self._run("uname -a")
        data['os_info']        = self._run("cat /etc/os-release 2>/dev/null | head -5")
        data['proc_version']   = self._run("cat /proc/version 2>/dev/null")

        ver_tuple = parse_kernel_version(data['kernel_version'])
        data['kernel_tuple'] = ver_tuple

        # Match against CVE database
        for min_v, max_v, cve_id, name, desc, url, severity in KERNEL_CVES:
            if min_v <= ver_tuple < max_v:
                data['vulnerable_cves'].append({
                    'cve'      : cve_id,
                    'name'     : name,
                    'desc'     : desc,
                    'url'      : url,
                    'severity' : severity,
                    'min_ver'  : '.'.join(str(x) for x in min_v),
                    'max_ver'  : '.'.join(str(x) for x in max_v),
                })
                if severity == 'CRITICAL':
                    data['critical_count'] += 1
                elif severity == 'HIGH':
                    data['high_count'] += 1

        self.findings = data
        return self.findings

    def display(self):
        d = self.findings
        info(f"Kernel Version : {d.get('kernel_version', 'N/A')}")
        info(f"Full uname -a  : {d.get('kernel_full', 'N/A')}")
        info(f"OS Info        : {d.get('os_info', 'N/A')[:80]}")

        cves = d.get('vulnerable_cves', [])
        if cves:
            print(f"\n  {Colors.RED}{Colors.BOLD}⚠  KERNEL CVE MATCHES ({len(cves)} found):{Colors.RESET}")
            for cve in cves:
                finding(cve['severity'],
                        f"{cve['cve']} – {cve['name']}")
                print(f"           Description : {cve['desc']}")
                print(f"           Affects     : kernel {cve['min_ver']} – {cve['max_ver']}")
                print(f"           {Colors.CYAN}Reference   : {cve['url']}{Colors.RESET}")
                print(f"           Mitigation  : Update kernel → sudo apt update && sudo apt upgrade -y")
                print()
            print(f"  {Colors.RED}CRITICAL CVEs: {d['critical_count']} | HIGH CVEs: {d['high_count']}{Colors.RESET}")
        else:
            ok(f"No known CVEs found for kernel {d.get('kernel_version', '')}")
            info("Note: This is a static CVE list. Check https://linuxkernelcves.com for latest entries.")

        print(f"\n  {Colors.CYAN}Manual verification resources:{Colors.RESET}")
        print(f"   → https://www.linuxkernelcves.com")
        print(f"   → https://nvd.nist.gov/vuln/search?query=linux+kernel")
        print(f"   → https://www.exploit-db.com/search?q=linux+kernel+privilege+escalation")
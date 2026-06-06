"""
Module: Misconfigured Service Scanner
Identifies systemd services running as root pointing to user-controlled files,
insecure PATH in service files, and sudo misconfigurations.

Commands used:
  systemctl list-units --type=service --all        → All services
  systemctl show <service> -p ExecStart,User       → Service properties
  cat /etc/systemd/system/*.service                → Raw service files
  sudo -l                                          → Sudo rules
  cat /etc/sudoers                                 → Sudoers file

References:
  https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
  https://gtfobins.github.io
"""

import subprocess
import os
import glob
from modules.banner import Colors, ok, warn, info, finding


# Dangerous sudo rules that allow escalation
DANGEROUS_SUDO_PATTERNS = [
    ('NOPASSWD.*ALL',        'CRITICAL', 'Full root access without password'),
    ('NOPASSWD.*/bin/bash',  'CRITICAL', 'Passwordless bash = root shell'),
    ('NOPASSWD.*/bin/sh',    'CRITICAL', 'Passwordless sh = root shell'),
    ('NOPASSWD.*/usr/bin/vi','CRITICAL', 'vi sudo → :!/bin/sh'),
    ('NOPASSWD.*/usr/bin/vim','CRITICAL','vim sudo → :!/bin/sh'),
    ('NOPASSWD.*/usr/bin/python','HIGH', 'python sudo → os.system()'),
    ('NOPASSWD.*/usr/bin/perl','HIGH',   'perl sudo → exec()'),
    ('NOPASSWD.*/usr/bin/find','HIGH',   'find sudo → -exec /bin/sh'),
    ('NOPASSWD.*/usr/bin/awk','HIGH',    'awk sudo → system()'),
    ('NOPASSWD.*/usr/bin/nmap','HIGH',   'nmap sudo → --interactive sh'),
    ('NOPASSWD.*/usr/bin/less','HIGH',   'less sudo → !/bin/sh'),
    ('NOPASSWD.*/usr/bin/more','HIGH',   'more sudo → !/bin/sh'),
    ('NOPASSWD.*/usr/bin/tar','HIGH',    'tar sudo → checkpoint exec'),
    ('NOPASSWD.*/usr/bin/env','HIGH',    'env sudo → PATH hijack'),
    ('env_keep.*LD_PRELOAD', 'CRITICAL', 'LD_PRELOAD kept → .so injection'),
    ('env_keep.*PYTHONPATH', 'HIGH',     'PYTHONPATH kept → python module hijack'),
]


class ServiceScanner:
    def __init__(self):
        self.findings = {}

    def _run(self, cmd, timeout=15):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip()
        except Exception:
            return ""

    def _check_service_files(self):
        """Inspect systemd service files for misconfigurations."""
        issues = []
        service_paths = [
            '/etc/systemd/system/',
            '/lib/systemd/system/',
            '/usr/lib/systemd/system/',
        ]

        for base in service_paths:
            for service_file in glob.glob(os.path.join(base, '*.service')):
                try:
                    with open(service_file, 'r', errors='ignore') as f:
                        content = f.read()

                    lines = content.splitlines()
                    exec_start  = ''
                    user        = 'root'  # default
                    has_path    = False

                    for line in lines:
                        line = line.strip()
                        if line.startswith('ExecStart='):
                            exec_start = line.replace('ExecStart=', '').strip()
                        if line.startswith('User='):
                            user = line.replace('User=', '').strip()
                        if line.startswith('Environment=') and 'PATH=' in line:
                            has_path = True

                    # Root-run service with user-writable ExecStart
                    if user in ('', 'root') and exec_start:
                        # Strip leading dashes/@ that systemd uses
                        exec_bin = exec_start.lstrip('-+@!').split()[0]
                        if exec_bin and os.path.exists(exec_bin):
                            if os.access(exec_bin, os.W_OK):
                                issues.append({
                                    'file'      : service_file,
                                    'exec'      : exec_bin,
                                    'severity'  : 'CRITICAL',
                                    'reason'    : f'Root service binary {exec_bin} is writable!',
                                })
                        elif exec_bin and '/' not in exec_bin:
                            # Relative path in ExecStart (PATH-dependent)
                            issues.append({
                                'file'    : service_file,
                                'exec'    : exec_bin,
                                'severity': 'HIGH',
                                'reason'  : f'Relative ExecStart path → PATH hijacking possible',
                            })

                except Exception:
                    continue

        return issues

    def _check_sudo(self):
        """Analyse sudo -l output for dangerous configurations."""
        sudo_output = self._run("sudo -l -n 2>/dev/null")
        if not sudo_output:
            sudo_output = self._run("sudo -l 2>&1 | head -30")

        issues = []
        import re
        for pattern, severity, description in DANGEROUS_SUDO_PATTERNS:
            if re.search(pattern, sudo_output, re.IGNORECASE):
                issues.append({
                    'pattern'    : pattern,
                    'severity'   : severity,
                    'description': description,
                    'raw'        : sudo_output,
                })

        return sudo_output, issues

    def _check_running_processes(self):
        """Find processes running as root that could be hijacked."""
        procs = []
        ps_raw = self._run("ps aux 2>/dev/null | grep '^root' | grep -v grep | head -20")
        for line in ps_raw.splitlines():
            parts = line.split(None, 10)
            if len(parts) >= 11:
                cmd = parts[10]
                # Flag processes running scripts from /tmp or /home
                if any(suspicious in cmd for suspicious in ['/tmp/', '/home/', '/var/tmp/']):
                    procs.append({'line': line, 'severity': 'HIGH', 'cmd': cmd})
        return procs

    def scan(self):
        data = {
            'service_issues'  : self._check_service_files(),
            'sudo_raw'        : '',
            'sudo_issues'     : [],
            'root_procs'      : self._check_running_processes(),
        }
        data['sudo_raw'], data['sudo_issues'] = self._check_sudo()
        self.findings = data
        return self.findings

    def display(self):
        d = self.findings

        # Sudo issues
        if d['sudo_issues']:
            print(f"\n  {Colors.RED}{Colors.BOLD}⚠  DANGEROUS SUDO CONFIGURATIONS:{Colors.RESET}")
            for issue in d['sudo_issues']:
                finding(issue['severity'], issue['description'])
                print(f"           {Colors.CYAN}Reference: https://gtfobins.github.io{Colors.RESET}")
        else:
            ok("No dangerous sudo configurations detected")

        if d['sudo_raw']:
            info(f"Sudo rules summary:\n         {Colors.WHITE}{d['sudo_raw'][:300]}{Colors.RESET}")

        # Service file issues
        if d['service_issues']:
            print(f"\n  {Colors.RED}Misconfigured service files:{Colors.RESET}")
            for issue in d['service_issues']:
                finding(issue['severity'], f"{issue['file']}")
                print(f"           Reason: {issue['reason']}")
        else:
            ok("No writable root service binaries found")

        # Suspicious root processes
        if d['root_procs']:
            print(f"\n  {Colors.YELLOW}Suspicious root processes (running from user paths):{Colors.RESET}")
            for p in d['root_procs']:
                finding(p['severity'], p['cmd'])
        else:
            ok("No suspicious root processes detected")
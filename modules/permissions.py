"""
Module: File & Directory Permission Scanner
Detects world-writable files, misconfigured sensitive files, and insecure home dirs.

Commands used:
  find / -writable -not -path '*/proc/*' 2>/dev/null   → Writable files
  ls -la /etc/passwd /etc/shadow /etc/sudoers           → Sensitive file perms
  find /home -maxdepth 2 -perm -o+r 2>/dev/null        → World-readable home dirs

References:
  https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
"""

import subprocess
import os
import stat
from modules.banner import Colors, ok, warn, info, finding

# Files that should NEVER be world-writable or world-readable
SENSITIVE_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/etc/crontab',
    '/etc/ssh/sshd_config',
    '/etc/hosts',
    '/root/.bashrc',
    '/root/.profile',
    '/root/.ssh/authorized_keys',
]

# Directories that should not be world-writable
SENSITIVE_DIRS = [
    '/etc',
    '/etc/cron.d',
    '/etc/cron.daily',
    '/etc/cron.hourly',
    '/etc/cron.monthly',
    '/etc/cron.weekly',
    '/etc/init.d',
    '/etc/systemd/system',
    '/usr/bin',
    '/usr/sbin',
    '/bin',
    '/sbin',
]


class PermissionScanner:
    def __init__(self):
        self.findings = {}

    def _run(self, cmd, timeout=30):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip()
        except Exception:
            return ""

    def _check_perms(self, path):
        """Return permission info for a file."""
        try:
            st   = os.stat(path)
            mode = st.st_mode
            return {
                'path'          : path,
                'exists'        : True,
                'world_writable': bool(mode & stat.S_IWOTH),
                'world_readable': bool(mode & stat.S_IROTH),
                'owner_writable': bool(mode & stat.S_IWUSR),
                'perms'         : oct(mode)[-3:],
                'owner_uid'     : st.st_uid,
            }
        except FileNotFoundError:
            return {'path': path, 'exists': False}
        except PermissionError:
            return {'path': path, 'exists': True, 'error': 'Permission denied'}

    def scan(self):
        data = {
            'sensitive_files'       : [],
            'world_writable_files'  : [],
            'world_writable_dirs'   : [],
            'writable_scripts'      : [],
            'passwd_writable'       : False,
            'shadow_readable'       : False,
            'home_dirs_exposed'     : [],
        }

        # Check sensitive files
        for f in SENSITIVE_FILES:
            perm = self._check_perms(f)
            if perm.get('exists'):
                data['sensitive_files'].append(perm)

        # Specific critical checks
        shadow_perm = self._check_perms('/etc/shadow')
        if shadow_perm.get('world_readable'):
            data['shadow_readable'] = True

        passwd_perm = self._check_perms('/etc/passwd')
        if passwd_perm.get('world_writable'):
            data['passwd_writable'] = True

        # World-writable files (excluding /proc, /sys, /dev)
        ww_raw = self._run(
            "find / -writable -type f "
            "-not -path '*/proc/*' "
            "-not -path '*/sys/*' "
            "-not -path '*/dev/*' "
            "-not -path '*/run/*' "
            "2>/dev/null | head -50",
            timeout=60
        )
        for line in ww_raw.splitlines():
            line = line.strip()
            if line:
                data['world_writable_files'].append(line)
                # Flag scripts in system dirs
                if any(d in line for d in ['/etc/', '/usr/', '/bin/', '/sbin/', '/opt/']):
                    data['writable_scripts'].append(line)

        # World-writable directories
        wwd_raw = self._run(
            "find / -writable -type d "
            "-not -path '*/proc/*' "
            "-not -path '*/sys/*' "
            "-not -path '*/dev/*' "
            "2>/dev/null | head -30",
            timeout=60
        )
        for line in wwd_raw.splitlines():
            line = line.strip()
            if line and line not in ['/tmp', '/var/tmp', '/dev/shm']:
                data['world_writable_dirs'].append(line)

        # Home directory exposures
        home_raw = self._run("ls -la /home/ 2>/dev/null")
        for line in home_raw.splitlines():
            if 'r-xr-x' in line or 'rwxrwx' in line:
                parts = line.split()
                if parts:
                    data['home_dirs_exposed'].append(line)

        self.findings = data
        return self.findings

    def display(self):
        d = self.findings

        # Critical flags
        if d['passwd_writable']:
            finding('CRITICAL', "/etc/passwd is WORLD WRITABLE → Add rouge root user!")
            print(f"           {Colors.YELLOW}Exploit: echo 'evil::0:0::/root:/bin/bash' >> /etc/passwd{Colors.RESET}")
        else:
            ok("/etc/passwd permissions are secure")

        if d['shadow_readable']:
            finding('CRITICAL', "/etc/shadow is WORLD READABLE → Dump and crack hashes!")
            print(f"           {Colors.YELLOW}Exploit: cat /etc/shadow | john --wordlist=rockyou.txt{Colors.RESET}")
        else:
            ok("/etc/shadow is not world-readable")

        # Sensitive files
        print(f"\n  {Colors.CYAN}Sensitive file permission audit:{Colors.RESET}")
        for f in d['sensitive_files']:
            if not f.get('exists'):
                continue
            perms = f.get('perms', '???')
            if f.get('world_writable'):
                finding('CRITICAL', f"{f['path']} [{perms}] → WORLD WRITABLE")
            elif f.get('world_readable') and 'shadow' in f['path']:
                finding('HIGH', f"{f['path']} [{perms}] → World readable (sensitive)")
            else:
                ok(f"{f['path']} [{perms}]")

        # Writable system scripts
        if d['writable_scripts']:
            print(f"\n  {Colors.RED}Writable files in system paths:{Colors.RESET}")
            for s in d['writable_scripts'][:10]:
                finding('HIGH', f"Writable system file: {s}")
        else:
            ok("No writable files in critical system paths")

        # World-writable unusual dirs
        if d['world_writable_dirs']:
            print(f"\n  {Colors.YELLOW}Unusual world-writable directories:{Colors.RESET}")
            for d_ in d['world_writable_dirs'][:10]:
                finding('MEDIUM', f"Writable dir: {d_}")

        info(f"Total world-writable files found: {len(d['world_writable_files'])}")
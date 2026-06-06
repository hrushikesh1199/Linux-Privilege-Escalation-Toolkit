"""
Module: System Information Collector
Gathers OS, kernel, user, and environment details.

Commands used:
  uname -a          → Full kernel info
  id                → Current user and groups
  whoami            → Username
  hostname          → Machine hostname
  cat /etc/os-release → OS distribution info
  env               → Environment variables (PATH hijack check)
  cat /etc/passwd   → User accounts
  cat /etc/group    → Groups
"""

import subprocess
import os
import platform
from modules.banner import Colors, ok, warn, info, finding


class SystemInfoScanner:
    def __init__(self):
        self.findings = {}

    def _run(self, cmd, shell=True):
        try:
            result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except Exception:
            return ""

    def scan(self):
        data = {}

        # Kernel & OS
        data['kernel']   = self._run("uname -a")
        data['os_name']  = self._run("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
        data['hostname'] = self._run("hostname")
        data['arch']     = platform.machine()

        # User context
        data['whoami']   = self._run("whoami")
        data['id']       = self._run("id")
        data['groups']   = self._run("groups")
        data['home']     = os.path.expanduser("~")

        # PATH analysis
        path_env = os.environ.get('PATH', '')
        data['path']     = path_env
        data['writable_path_dirs'] = []
        for p in path_env.split(':'):
            if p and os.path.isdir(p) and os.access(p, os.W_OK):
                data['writable_path_dirs'].append(p)

        # Sudo privileges
        data['sudo_l']   = self._run("sudo -l -n 2>/dev/null || echo 'No sudo or requires password'")

        # Network info
        data['ip_addr']  = self._run("ip addr show 2>/dev/null | grep 'inet ' | awk '{print $2}'")
        data['netstat']  = self._run("ss -tlnp 2>/dev/null | head -20")

        # Environment variables of interest
        data['interesting_env'] = {}
        for var in ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'PERL5LIB', 'RUBYLIB']:
            val = os.environ.get(var, '')
            if val:
                data['interesting_env'][var] = val

        self.findings = data
        return self.findings

    def display(self):
        d = self.findings
        info(f"Hostname : {d.get('hostname', 'N/A')}")
        info(f"OS       : {d.get('os_name', 'N/A')}")
        info(f"Kernel   : {d.get('kernel', 'N/A')}")
        info(f"Arch     : {d.get('arch', 'N/A')}")
        info(f"User     : {d.get('id', 'N/A')}")
        info(f"Home Dir : {d.get('home', 'N/A')}")

        writable = d.get('writable_path_dirs', [])
        if writable:
            for p in writable:
                finding('HIGH', f"Writable PATH directory: {Colors.RED}{p}{Colors.RESET} → PATH Hijacking possible")
        else:
            ok("No writable directories in PATH")

        env = d.get('interesting_env', {})
        if env:
            for k, v in env.items():
                finding('MEDIUM', f"Dangerous env var set: {k}={v}")

        sudo = d.get('sudo_l', '')
        if 'NOPASSWD' in sudo:
            finding('CRITICAL', f"Sudo NOPASSWD privilege found!\n         → {sudo}")
        elif '(ALL)' in sudo:
            finding('HIGH', f"Broad sudo access detected:\n         → {sudo}")
        elif sudo:
            info(f"Sudo privileges:\n         {sudo}")
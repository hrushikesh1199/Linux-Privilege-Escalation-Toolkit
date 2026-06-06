#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          Linux Privilege Escalation Automation Toolkit               ║
║                  Version 1.0 | Red-Blue Team Tool                    ║
║         Author: Hrushikesh Pawar | github.com/hrushikesh1199     ║
╚══════════════════════════════════════════════════════════════════════╝

DISCLAIMER:
This toolkit is intended STRICTLY for educational purposes, authorized
penetration testing, and defensive security auditing. Running this tool
on systems without explicit written permission is illegal and unethical.
The author assumes no responsibility for misuse.

Usage:
    sudo python3 privesc_toolkit.py                  # Full scan
    sudo python3 privesc_toolkit.py --module suid    # Single module
    sudo python3 privesc_toolkit.py --output report  # Export report
    sudo python3 privesc_toolkit.py --help           # Show help
"""

import os
import sys
import argparse
import datetime
import platform
import json

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from modules.system_info      import SystemInfoScanner
from modules.suid_scanner     import SUIDScanner
from modules.permissions      import PermissionScanner
from modules.services         import ServiceScanner
from modules.cron_scanner     import CronScanner
from modules.kernel_cve       import KernelCVEScanner
from modules.report_generator import ReportGenerator
from modules.banner           import print_banner, print_section, Colors

__version__ = "1.0.0"
__author__  = "Hrushikesh Pawar"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Linux Privilege Escalation Automation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 privesc_toolkit.py
  sudo python3 privesc_toolkit.py --module suid
  sudo python3 privesc_toolkit.py --module cron
  sudo python3 privesc_toolkit.py --output /tmp/report
  sudo python3 privesc_toolkit.py --format json
  sudo python3 privesc_toolkit.py --quiet

Modules:
  sysinfo   - System information collection
  suid      - SUID/SGID binary discovery
  perms     - File & directory permission analysis
  services  - Misconfigured service detection
  cron      - Cron job vulnerability scan
  kernel    - Kernel CVE detection

Reference:
  GTFOBins  : https://gtfobins.github.io
  LinPEAS   : https://github.com/carlospolop/PEASS-ng
  CVE DB    : https://cve.mitre.org
        """
    )
    parser.add_argument('--module', choices=['sysinfo','suid','perms','services','cron','kernel'],
                        help='Run a specific module only')
    parser.add_argument('--output', metavar='PATH',
                        help='Output path for report (without extension)')
    parser.add_argument('--format', choices=['txt','json','both'], default='both',
                        help='Report output format (default: both)')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress banner and progress output')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    return parser.parse_args()


def check_root():
    """
    Root check for Linux.
    Skip on Windows.
    """

    if os.name == "nt":
        print(f"\n{Colors.YELLOW}[!] Windows detected. Root check skipped.{Colors.RESET}\n")
        return

    if hasattr(os, "geteuid"):
        if os.geteuid() != 0:
            print(
                f"\n{Colors.YELLOW}[!] WARNING: Not running as root. "
                f"Some checks may be incomplete.{Colors.RESET}"
            )

def run_all_modules(args, quiet=False):
    """Execute all scanning modules and collect findings."""
    all_findings = {}
    start_time   = datetime.datetime.now()

    modules = [
        ("System Information",      SystemInfoScanner),
        ("SUID/SGID Binaries",      SUIDScanner),
        ("File Permissions",        PermissionScanner),
        ("Misconfigured Services",  ServiceScanner),
        ("Cron Job Analysis",       CronScanner),
        ("Kernel CVE Detection",    KernelCVEScanner),
    ]

    # If single module requested, filter
    module_map = {
        'sysinfo': 'System Information',
        'suid':    'SUID/SGID Binaries',
        'perms':   'File Permissions',
        'services':'Misconfigured Services',
        'cron':    'Cron Job Analysis',
        'kernel':  'Kernel CVE Detection',
    }
    if args.module:
        target = module_map[args.module]
        modules = [(name, cls) for name, cls in modules if name == target]

    for name, ScannerClass in modules:
        if not quiet:
            print_section(name)
        try:
            scanner  = ScannerClass()
            findings = scanner.scan()
            all_findings[name] = findings
            if not quiet:
                scanner.display()
        except Exception as e:
            all_findings[name] = {"error": str(e)}
            print(f"{Colors.RED}[-] Error in {name}: {e}{Colors.RESET}")

    end_time = datetime.datetime.now()
    elapsed  = (end_time - start_time).seconds

    return all_findings, start_time, elapsed


def main():
    args = parse_args()

    if not args.quiet:
        print_banner()

    check_root()

    print(f"{Colors.CYAN}[*] Starting scan at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")

    findings, start_time, elapsed = run_all_modules(args, quiet=args.quiet)

    # Determine output path
    timestamp   = start_time.strftime("%Y%m%d_%H%M%S")
    output_base = args.output or f"reports/privesc_report_{timestamp}"
    os.makedirs(os.path.dirname(output_base) if os.path.dirname(output_base) else "reports", exist_ok=True)

    # Generate reports
    generator = ReportGenerator(findings, start_time, elapsed)

    if args.format in ('txt', 'both'):
        txt_path = output_base + ".txt"
        generator.export_txt(txt_path)
        print(f"\n{Colors.GREEN}[+] Text report saved  → {txt_path}{Colors.RESET}")

    if args.format in ('json', 'both'):
        json_path = output_base + ".json"
        generator.export_json(json_path)
        print(f"{Colors.GREEN}[+] JSON report saved  → {json_path}{Colors.RESET}")

    print(f"\n{Colors.CYAN}[*] Scan completed in {elapsed}s | Total findings: {generator.total_findings()}{Colors.RESET}")
    print(f"{Colors.RED}[!] REMINDER: Use this toolkit only on systems you own or have written permission to test.{Colors.RESET}\n")


if __name__ == "__main__":
    main()
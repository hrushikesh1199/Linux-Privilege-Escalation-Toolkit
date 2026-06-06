"""
Banner and color utilities for the Linux Privilege Escalation Toolkit.
"""

import os
import sys


class Colors:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'

    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ''
        cls.MAGENTA = cls.CYAN = cls.WHITE = cls.BOLD = cls.RESET = ''


SEVERITY_COLORS = {
    'CRITICAL': Colors.RED,
    'HIGH':     Colors.RED,
    'MEDIUM':   Colors.YELLOW,
    'LOW':      Colors.GREEN,
    'INFO':     Colors.CYAN,
}

BANNER = r"""
{}{}
  ██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗
  ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝
  ██████╔╝██████╔╝██║██║   ██║█████╗  ███████╗██║
  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║██║
  ██║     ██║  ██║██║ ╚████╔╝ ███████╗███████║╚██████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝

  {}Linux Privilege Escalation Automation Toolkit v1.0{}
  {}Author : Hrushikesh Chaudhari{}
  {}GitHub : https://github.com/hrushikesh1199{}
  {}Purpose: Authorized Security Auditing | Red-Blue Team{}

  {}[!] For educational & authorized use ONLY{}
{}═══════════════════════════════════════════════════════════╗
""".format(
    Colors.RED, Colors.BOLD,
    Colors.WHITE, Colors.RESET,
    Colors.CYAN, Colors.RESET,
    Colors.CYAN, Colors.RESET,
    Colors.CYAN, Colors.RESET,
    Colors.YELLOW, Colors.RESET,
    Colors.RED,
)


def print_banner():
    print(BANNER)


def print_section(title):
    width = 60
    bar   = "─" * width
    print(f"\n{Colors.BLUE}{Colors.BOLD}┌{bar}┐")
    print(f"│  {title:<{width-2}}│")
    print(f"└{bar}┘{Colors.RESET}")


def severity_label(level):
    color = SEVERITY_COLORS.get(level.upper(), Colors.WHITE)
    return f"{color}[{level.upper()}]{Colors.RESET}"


def finding(severity, msg):
    print(f"  {severity_label(severity)} {msg}")


def ok(msg):
    print(f"  {Colors.GREEN}[✓]{Colors.RESET} {msg}")


def warn(msg):
    print(f"  {Colors.YELLOW}[!]{Colors.RESET} {msg}")


def info(msg):
    print(f"  {Colors.CYAN}[*]{Colors.RESET} {msg}")
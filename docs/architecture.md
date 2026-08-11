# Project Architecture

The Linux Privilege Escalation Toolkit follows a modular security auditing architecture.

## Workflow

```text
User
  |
  v
CLI Interface
  |
  v
Security Scanners
  |
  +-- SUID/SGID Scanner
  |
  +-- File Permission Scanner
  |
  +-- Cron Job Scanner
  |
  +-- Systemd Scanner
  |
  +-- Sudo Configuration Scanner
  |
  +-- Kernel CVE Scanner
  |
  v
Analysis Engine
  |
  v
Report Generator
  |
  +-- JSON Report
  |
  +-- TXT Report
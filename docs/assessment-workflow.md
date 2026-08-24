# Linux Privilege Escalation Assessment Workflow

A structured workflow for identifying, validating, and documenting Linux privilege-escalation risks during authorized security assessments.

---

## 1. Scope and Authorization

Before beginning an assessment:

- Confirm explicit authorization.
- Identify target systems.
- Define testing boundaries.
- Confirm allowed testing techniques.
- Establish reporting requirements.
- Avoid actions that could disrupt production systems.

---

## 2. System Enumeration

Collect basic system information:

```text
Hostname
Operating System
Kernel Version
Architecture
Current User
User ID
Group Memberships
Running Processes
Environment


## Key Questions

- Who am I?
- What groups do I belong to?
- What operating system is running?
- Is the kernel outdated?
- Which privileged processes are active?

---

## 3. User and Group Enumeration

Review:

- `/etc/passwd`
- `/etc/group`
- Home directories
- Service accounts
- Current user memberships

Look for:

- Unexpected administrative groups
- Writable home directories
- Service accounts with excessive privileges
- Shared or unusual accounts

---

## 4. Sudo Assessment

Review the current user's sudo permissions:

    sudo -l

Assess:

- Commands allowed without a password
- Commands executable as another user
- Wildcard permissions
- Dangerous administrative utilities
- Environment-related permissions

**Security Principle**

Sudo permissions should follow the principle of least privilege.

---

## 5. SUID and SGID Assessment

Identify SUID binaries:

    find / -perm -4000 -type f 2>/dev/null

Identify SGID binaries:

    find / -perm -2000 -type f 2>/dev/null

Classify discovered binaries as:

    Expected
          ↓
    Unexpected
          ↓
    Potentially Dangerous
          ↓
    Requires Validation

The toolkit's SUID scanner helps automate this stage.

---

## 6. Linux Capabilities

Identify assigned capabilities:

    getcap -r / 2>/dev/null

Pay particular attention to capabilities that can provide elevated privileges or bypass normal file restrictions.

Record:

- Executable path
- Capability
- Owning package
- Required business purpose
- Security impact

---

## 7. Scheduled Tasks

Review scheduled execution mechanisms:

- `/etc/crontab`
- `/etc/cron.d/`
- `/etc/cron.daily/`
- `/etc/cron.hourly/`
- `/etc/cron.weekly/`
- `/etc/cron.monthly/`

Look for:

- Privileged scheduled jobs
- Writable scripts
- Writable directories
- Unsafe executable paths
- Unexpected scheduled tasks

---

## 8. File and Directory Permissions

Review permissions on:

- Root-owned files
- Executable scripts
- Configuration files
- Service files
- Application directories
- Authentication-related files

Important questions:

    Who owns the file?
            ↓
    Who can modify it?
            ↓
    Who executes it?
            ↓
    Does a privileged process depend on it?

---

## 9. Running Services

Identify active services and processes.

Review:

- Root-owned services
- Custom applications
- Service configuration
- Service executable permissions
- Service dependencies

The objective is to identify configurations where a low-privileged user can influence a privileged process.

---

## 10. Environment and PATH

Review:

    echo $PATH
    env

Look for:

- Writable directories in PATH
- Unsafe environment variables
- Relative executable paths
- User-controlled configuration
- Privileged processes depending on unsafe environment data

---

## 11. Network Enumeration

Identify listening services:

    ss -tulpn

Assess:

- Local-only services
- Unexpected listeners
- Administrative interfaces
- Internal applications
- Services requiring additional security review

---

## 12. Kernel and Package Assessment

Collect:

    uname -a
    cat /etc/os-release

Review installed software and versions.

Consider:

- Missing security patches
- Outdated kernels
- Vulnerable privileged applications
- Known CVEs

Kernel or package findings should be validated against the specific system configuration before being classified as exploitable.

---

## 13. Sensitive Information

During an authorized assessment, identify improperly exposed:

- Passwords
- API keys
- Database credentials
- Private keys
- Tokens
- Service credentials
- Application secrets

Do not unnecessarily copy or expose sensitive information.

---

## 14. Finding Validation

Not every unusual configuration is automatically a vulnerability.

For each finding determine:

    Configuration
         ↓
    Exposure
         ↓
    Affected Privilege
         ↓
    Security Impact
         ↓
    Validation
         ↓
    Risk Classification

Document evidence before assigning a final severity.

---

## 15. Reporting

Each confirmed finding should contain:

### Finding

A concise vulnerability title.

### Severity

Critical / High / Medium / Low / Informational.

### Affected Component

File, binary, service, configuration, or account.

### Evidence

Relevant configuration or scanner output.

### Impact

Explain the potential security consequence.

### Recommendation

Provide a practical remediation.

### Retest

Document whether remediation was successful.

---

## Assessment Flow

    Authorization
          ↓
    System Enumeration
          ↓
    Users & Groups
          ↓
    Sudo Permissions
          ↓
    SUID / SGID
          ↓
    Linux Capabilities
          ↓
    Cron / Scheduled Tasks
          ↓
    File Permissions
          ↓
    Services
          ↓
    Environment / PATH
          ↓
    Network Services
          ↓
    Kernel / Packages
          ↓
    Finding Validation
          ↓
    Reporting
          ↓
    Remediation
          ↓
    Retesting

---

## Toolkit Mapping

| Assessment Area | Toolkit Component |
|---|---|
| System Enumeration | system_info.py |
| SUID / SGID | suid_scanner.py |
| Kernel Assessment | kernel_cve.py |
| File Permissions | permissions.py |
| Cron Jobs | cron_scanner.py |
| Services | services.py |
| Reporting | report_generator.py |
| Terminal Output | banner.py |

---

## Defensive Priorities

Organizations can reduce privilege-escalation risk by:

- Applying least privilege
- Minimizing SUID/SGID binaries
- Reviewing sudo permissions
- Removing unnecessary capabilities
- Maintaining security patches
- Hardening services
- Protecting sensitive credentials
- Monitoring privileged activity
- Reviewing file permissions
- Regularly performing security assessments

---

*This workflow is intended for authorized security assessments, defensive auditing, education, and controlled laboratory environments.*
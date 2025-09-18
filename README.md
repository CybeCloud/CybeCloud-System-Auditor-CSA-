# CybeCloud-System-Auditor-CSA
CybeCloud AuditKit (v1.0)— lightweight Windows system security and configuration assessment toolkit for authorized audits and admin inspections.

CybeCloud AuditKit is a lightweight Windows system auditing toolkit that collects system information, inspects user context and privileges, finds potentially vulnerable services and scheduled tasks, inspects network configuration, verifies core security settings, lists installed software and searches for likely sensitive files. It’s built for authorized system administration and penetration testing — not for malicious use.


SAT provides a non-destructive, read-only audit of Windows systems. It collects host information, enumerates user privileges, checks for insecure services and scheduled tasks, validates network and security configurations, inventories installed software, and searches for potentially sensitive files.

This script is designed strictly for authorized use in environments where you have explicit permission to audit.

**Features**
**1. System Information**

Collects OS name, version, manufacturer, and domain details.

Displays hardware model and recent boot time.

Retrieves and lists the most recent installed hotfixes/patches.

**2. User Context and Privileges**

Displays the current user context with associated privileges.

Enumerates members of the local Administrators group.

Helps identify accounts with elevated or unexpected privileges.

**3. Service Analysis**

Detects unquoted service paths vulnerable to path injection.

Examines service binaries for weak file system permissions that may be abused for privilege escalation.

Displays results in a clear, tabular format.

**4. Scheduled Task Discovery**

Enumerates active scheduled tasks.

Filters out Microsoft defaults to highlight custom or third-party tasks.

Useful for detecting persistence mechanisms.

**5. Network Configuration**

Displays active network interfaces, IP addresses, and gateways.

Lists listening TCP ports and their owning processes.

Extracts Wi-Fi profiles and shows stored keys (if accessible).

Provides a quick overview of network exposure and saved credentials.

**6. Security Settings**

Verifies User Account Control (UAC) status.

Checks Local Security Authority (LSA) protection status.

Queries Windows Defender / Security Center status, including AV and real-time protection.

**7. Installed Software Inventory**

Enumerates installed applications from registry locations.

Excludes Microsoft/Windows entries to focus on third-party software.

Displays software name, version, and publisher.

**8. Sensitive File Search**

Recursively searches common directories (ProgramData, AppData, Documents, root of C:\) for sensitive file patterns.

Patterns include credentials, configuration files, keys, and common plaintext formats.

Outputs up to 5 matches per pattern per location.

Intended as a heuristic discovery aid (false positives possible).

**Execution Modes**

**Full Audit**
**Runs all modules.**

Start-SystemAudit


**Quick Audit**
R**uns only core checks (System + User).**

Start-SystemAudit -Quick


**Stealth Mode**
**Suppresses banner and introduces random delays.**

Start-SystemAudit -Stealth

Output

**Audit results are printed in grouped sections for easy interpretation:**

=== SYSTEM INFORMATION ===  
=== USER CONTEXT ===  
=== SERVICE ANALYSIS ===  
=== SCHEDULED TASKS ===  
=== NETWORK CONFIGURATION ===  
=== SECURITY SETTINGS ===  
=== INSTALLED SOFTWARE ===  
=== SENSITIVE FILE SEARCH ===  


Each section is formatted as tables or structured text. Output can be redirected to a file for later review:

Start-SystemAudit | Out-File audit-results.txt

Installation

Save the script as AuditKit.ps1.

Launch PowerShell with elevated privileges (recommended).

Allow script execution in the current session:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\AuditKit.ps1

Security Considerations

**Read-only: The script does not modify system state.**

**Privileges:** Some checks require administrative rights. Without elevation, results may be incomplete.

**Sensitive Data:** Output may expose passwords, Wi-Fi keys, or sensitive file paths. Treat results as confidential.

**False Positives:** Sensitive file search uses broad patterns; validation is required.

Intended Use & Legal Notice

**This toolkit is intended for:**

System administration and configuration hygiene.

Authorized penetration testing.

Incident response and blue-team triage.

Do not run this script on systems without explicit authorization. Unauthorized use may violate laws and organizational policies.

Contribution & Roadmap

**Future development goals include:**

JSON/CSV export options.

Modular reporting per environment.

Enhanced permission analysis for services and files.

Broader heuristics for sensitive data detection.

Contributions are welcome. Feature requests, bug reports, and pull requests should be submitted via the project repository.

**Summary**

CybeCloud Auditkit v1.0 delivers a comprehensive Windows auditing capability in a single PowerShell script. It is lightweight, non-intrusive, and effective for quickly surfacing security gaps and misconfigurations.

Network and Wi-Fi profile queries may expose secrets if run on shared machines — treat outputs as sensitive.

Contribution & roadmap

**Contributions welcome:** add modular checks, export options (JSON/CSV), improved permission parsing, or granular reporting. Open issues for specific feature requests or bug reports.

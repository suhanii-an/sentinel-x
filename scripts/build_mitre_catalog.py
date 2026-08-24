#!/usr/bin/env python3
"""Build the local MITRE ATT&CK catalogue shipped in ``data/mitre/``.

SENTINEL-X ships a *curated subset* of ATT&CK Enterprise: the tactics, the
techniques the platform actually detects, and enough neighbouring techniques for
the coverage view to be meaningful. Shipping the full 25 MB STIX bundle would add
weight without adding capability, and vendoring a partial copy silently would be
worse than saying so.

Technique IDs, names and tactic assignments follow ATT&CK Enterprise. Nothing in
this file is invented: if a technique is not in ATT&CK, it does not appear here,
and the platform never mints an ID of its own.

To refresh against the authoritative source, see ``scripts/refresh_mitre.py``,
which pulls the official MITRE CTI bundle and regenerates these files.

Usage:
    python scripts/build_mitre_catalog.py
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "data" / "mitre"

ATTACK_URL = "https://attack.mitre.org"

# (tactic_id, name, shortname, kill-chain order, description)
TACTICS = [
    ("TA0043", "Reconnaissance", "reconnaissance", 1,
     "The adversary is gathering information they can use to plan future operations."),
    ("TA0042", "Resource Development", "resource-development", 2,
     "The adversary is establishing resources they can use to support operations."),
    ("TA0001", "Initial Access", "initial-access", 3,
     "The adversary is trying to get into your network."),
    ("TA0002", "Execution", "execution", 4,
     "The adversary is trying to run malicious code."),
    ("TA0003", "Persistence", "persistence", 5,
     "The adversary is trying to maintain their foothold."),
    ("TA0004", "Privilege Escalation", "privilege-escalation", 6,
     "The adversary is trying to gain higher-level permissions."),
    ("TA0005", "Defense Evasion", "defense-evasion", 7,
     "The adversary is trying to avoid being detected."),
    ("TA0006", "Credential Access", "credential-access", 8,
     "The adversary is trying to steal account names and passwords."),
    ("TA0007", "Discovery", "discovery", 9,
     "The adversary is trying to figure out your environment."),
    ("TA0008", "Lateral Movement", "lateral-movement", 10,
     "The adversary is trying to move through your environment."),
    ("TA0009", "Collection", "collection", 11,
     "The adversary is trying to gather data of interest to their goal."),
    ("TA0011", "Command and Control", "command-and-control", 12,
     "The adversary is trying to communicate with compromised systems to control them."),
    ("TA0010", "Exfiltration", "exfiltration", 13,
     "The adversary is trying to steal data."),
    ("TA0040", "Impact", "impact", 14,
     "The adversary is trying to manipulate, interrupt or destroy your systems and data."),
]

LINUX_WIN = ["Linux", "Windows", "macOS"]
CLOUD = ["IaaS", "SaaS", "Identity Provider", "Office Suite"]

# (id, name, [tactics], platforms, description, detection_guidance)
TECHNIQUES = [
    ("T1110", "Brute Force", ["TA0006"], LINUX_WIN + CLOUD,
     "Adversaries systematically guess credentials when they do not have them.",
     "Monitor authentication logs for repeated failures from one source, and for failures spread thinly across many accounts."),
    ("T1110.001", "Brute Force: Password Guessing", ["TA0006"], LINUX_WIN + CLOUD,
     "Repeated authentication attempts against one or more accounts using a list of likely passwords.",
     "Threshold on authentication failures grouped by source address."),
    ("T1110.003", "Brute Force: Password Spraying", ["TA0006"], LINUX_WIN + CLOUD,
     "A small number of common passwords tried against many accounts to stay below lockout thresholds.",
     "Count distinct target accounts per source, not attempts per account."),
    ("T1110.004", "Brute Force: Credential Stuffing", ["TA0006"], LINUX_WIN + CLOUD,
     "Credentials from an unrelated breach replayed against the target.",
     "High failure volume with near-zero repetition of the same username/password pair."),
    ("T1078", "Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"], LINUX_WIN + CLOUD,
     "Adversaries use legitimate credentials, which bypasses controls that look for malicious code.",
     "Baseline per-account behaviour: source addresses, hours, and hosts accessed. Alert on multi-factor deviation, not single novelty."),
    ("T1078.002", "Valid Accounts: Domain Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"], ["Windows"],
     "Use of compromised domain credentials, which typically grant access across many systems.",
     "Correlate a single domain account authenticating to unusual numbers of hosts."),
    ("T1078.003", "Valid Accounts: Local Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"], LINUX_WIN,
     "Use of local account credentials configured by an administrator or by the operating system.",
     "Monitor local account use on systems where interactive local login is not expected."),
    ("T1078.004", "Valid Accounts: Cloud Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"], CLOUD,
     "Use of compromised cloud identities to access control planes and data.",
     "Baseline per-identity API usage, source address and MFA state; alert on combined deviation."),
    ("T1087", "Account Discovery", ["TA0007"], LINUX_WIN + CLOUD,
     "Adversaries enumerate accounts to understand which identities exist and which are privileged.",
     "Detect bursts of enumeration commands rather than any single command."),
    ("T1087.001", "Account Discovery: Local Account", ["TA0007"], LINUX_WIN,
     "Enumeration of local accounts via commands such as id, whoami, and reads of /etc/passwd.",
     "Correlate several enumeration categories from one account within a short window."),
    ("T1087.002", "Account Discovery: Domain Account", ["TA0007"], ["Windows"],
     "Enumeration of domain accounts via net, dsquery and directory queries.",
     "Windows 4798/4799 events and net.exe execution with account arguments."),
    ("T1087.004", "Account Discovery: Cloud Account", ["TA0007"], CLOUD,
     "Enumeration of cloud identities via IAM list and describe APIs.",
     "Burst of distinct read-only IAM calls from one identity."),
    ("T1082", "System Information Discovery", ["TA0007"], LINUX_WIN,
     "Collection of host details such as OS version, architecture and hardware.",
     "uname, systeminfo, hostnamectl executions, particularly alongside other discovery."),
    ("T1033", "System Owner/User Discovery", ["TA0007"], LINUX_WIN,
     "Identification of the primary user or currently logged-on users.",
     "whoami, w, last, and query user executions."),
    ("T1057", "Process Discovery", ["TA0007"], LINUX_WIN,
     "Enumeration of running processes to identify defences and valuable software.",
     "ps, tasklist and Get-Process executions in sequence with other discovery."),
    ("T1069", "Permission Groups Discovery", ["TA0007"], LINUX_WIN + CLOUD,
     "Enumeration of group memberships to find privileged principals.",
     "groups, net group, and cloud group-listing APIs."),
    ("T1069.003", "Permission Groups Discovery: Cloud Groups", ["TA0007"], CLOUD,
     "Enumeration of cloud group membership and role assignment.",
     "ListGroups, ListGroupsForUser and equivalent APIs."),
    ("T1046", "Network Service Discovery", ["TA0007"], LINUX_WIN + ["IaaS"],
     "Scanning for reachable services to identify lateral movement paths.",
     "Many short-lived connections from one host to many destinations or ports."),
    ("T1518", "Software Discovery", ["TA0007"], LINUX_WIN + CLOUD,
     "Enumeration of installed software, often to identify security tooling.",
     "Package manager queries and registry enumeration."),
    ("T1526", "Cloud Service Discovery", ["TA0007"], CLOUD,
     "Enumeration of available cloud services and their configuration.",
     "Describe and list API calls across multiple services from one identity."),
    ("T1580", "Cloud Infrastructure Discovery", ["TA0007"], ["IaaS"],
     "Enumeration of compute, storage and networking resources in a cloud account.",
     "DescribeInstances, ListBuckets and similar inventory calls."),
    ("T1059", "Command and Scripting Interpreter", ["TA0002"], LINUX_WIN + CLOUD,
     "Execution of commands and scripts through interpreters.",
     "Process creation events for shells and interpreters, with attention to unusual parents."),
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", ["TA0002"], ["Windows"],
     "Use of PowerShell to execute commands and scripts.",
     "Encoded command arguments, unusual parent processes, and script block logging."),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell", ["TA0002"], ["Linux", "macOS"],
     "Use of Unix shells to execute commands and scripts.",
     "Shell processes spawned by services or web servers rather than by login sessions."),
    ("T1548", "Abuse Elevation Control Mechanism", ["TA0004", "TA0005"], LINUX_WIN + CLOUD,
     "Circumvention of mechanisms that control elevated privilege.",
     "Correlate privilege enumeration with successful elevation shortly afterwards."),
    ("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", ["TA0004", "TA0005"], ["Linux", "macOS"],
     "Abuse of setuid/setgid binaries to execute code with the file owner's privileges.",
     "Filesystem searches for the setuid bit, and changes to setuid permissions."),
    ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ["TA0004", "TA0005"], ["Linux", "macOS"],
     "Abuse of sudo configuration or cached credentials to elevate privileges.",
     "sudo invocations to root, particularly interactive shells, and sudoers modification."),
    ("T1068", "Exploitation for Privilege Escalation", ["TA0004"], LINUX_WIN,
     "Exploitation of a software vulnerability to gain higher privileges.",
     "Unexpected privileged process ancestry, and crashes preceding privileged execution."),
    ("T1134", "Access Token Manipulation", ["TA0004", "TA0005"], ["Windows"],
     "Manipulation of access tokens to operate under a different security context.",
     "Assignment of sensitive privileges such as SeDebugPrivilege at logon."),
    ("T1098", "Account Manipulation", ["TA0003", "TA0004"], LINUX_WIN + CLOUD,
     "Modification of accounts to maintain or elevate access.",
     "Group membership changes, credential additions and permission grants."),
    ("T1098.001", "Account Manipulation: Additional Cloud Credentials", ["TA0003", "TA0004"], CLOUD,
     "Creation of additional credentials on an identity to retain access.",
     "CreateAccessKey and equivalent calls, especially following enumeration."),
    ("T1098.003", "Account Manipulation: Additional Cloud Roles", ["TA0003", "TA0004"], CLOUD,
     "Assignment of additional roles or policies to an identity.",
     "Policy attachment events referencing high-privilege policies."),
    ("T1098.004", "Account Manipulation: SSH Authorized Keys", ["TA0003", "TA0004"], ["Linux", "macOS", "IaaS"],
     "Addition of SSH public keys to authorized_keys files to retain access.",
     "File integrity monitoring on authorized_keys across the estate."),
    ("T1136", "Create Account", ["TA0003"], LINUX_WIN + CLOUD,
     "Creation of a new account to maintain access.",
     "Account creation events, with particular attention to privileged UIDs and groups."),
    ("T1136.001", "Create Account: Local Account", ["TA0003"], LINUX_WIN,
     "Creation of a local account on a compromised system.",
     "useradd/net user events; a second UID 0 account is unambiguous."),
    ("T1136.003", "Create Account: Cloud Account", ["TA0003"], CLOUD,
     "Creation of a cloud identity to maintain access.",
     "CreateUser and CreateRole calls from identities that do not normally provision."),
    ("T1053", "Scheduled Task/Job", ["TA0002", "TA0003", "TA0004"], LINUX_WIN,
     "Scheduling of code to run automatically, providing execution and persistence.",
     "Creation of scheduled tasks and cron entries, especially outside change windows."),
    ("T1053.003", "Scheduled Task/Job: Cron", ["TA0002", "TA0003", "TA0004"], ["Linux", "macOS"],
     "Use of cron to schedule execution of malicious code.",
     "File creation in /etc/cron.* and /var/spool/cron."),
    ("T1053.005", "Scheduled Task/Job: Scheduled Task", ["TA0002", "TA0003", "TA0004"], ["Windows"],
     "Use of the Windows Task Scheduler to execute code.",
     "Event ID 4698 and file creation under System32\\Tasks."),
    ("T1543", "Create or Modify System Process", ["TA0003", "TA0004"], LINUX_WIN,
     "Creation or modification of system-level services to execute code repeatedly.",
     "Service installation events and unit file creation."),
    ("T1543.002", "Create or Modify System Process: Systemd Service", ["TA0003", "TA0004"], ["Linux"],
     "Creation or modification of systemd services for persistence.",
     "File creation under /etc/systemd/system and /lib/systemd/system."),
    ("T1543.003", "Create or Modify System Process: Windows Service", ["TA0003", "TA0004"], ["Windows"],
     "Creation or modification of Windows services for persistence.",
     "Event ID 7045 and service configuration changes."),
    ("T1021", "Remote Services", ["TA0008"], LINUX_WIN + CLOUD,
     "Use of valid accounts with remote services to move between systems.",
     "Authentication to hosts an account does not normally access."),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", ["TA0008"], ["Windows"],
     "Use of RDP to interactively access remote systems.",
     "Logon type 10 events and connections to port 3389."),
    ("T1021.004", "Remote Services: SSH", ["TA0008"], ["Linux", "macOS", "IaaS"],
     "Use of SSH to access remote systems.",
     "Internal host-to-host SSH, particularly to hosts outside the account's baseline."),
    ("T1021.006", "Remote Services: Windows Remote Management", ["TA0008"], ["Windows"],
     "Use of WinRM to execute commands on remote systems.",
     "Connections to ports 5985/5986 and WSMan provider activity."),
    ("T1570", "Lateral Tool Transfer", ["TA0008"], LINUX_WIN,
     "Copying of tools between systems inside the environment.",
     "File writes to newly accessed hosts shortly after authentication."),
    ("T1105", "Ingress Tool Transfer", ["TA0011"], LINUX_WIN,
     "Transfer of tools from an external system into the environment.",
     "curl/wget/certutil executions with remote URLs on servers."),
    ("T1071", "Application Layer Protocol", ["TA0011"], LINUX_WIN + CLOUD,
     "Use of standard application protocols to blend command and control with normal traffic.",
     "Beaconing patterns and connections to indicators from threat intelligence."),
    ("T1071.001", "Application Layer Protocol: Web Protocols", ["TA0011"], LINUX_WIN,
     "Use of HTTP/HTTPS for command and control.",
     "Regular-interval outbound connections with small, consistent payload sizes."),
    ("T1552", "Unsecured Credentials", ["TA0006"], LINUX_WIN + CLOUD,
     "Discovery of credentials stored insecurely on systems.",
     "Access to credential files, key material and configuration containing secrets."),
    ("T1552.004", "Unsecured Credentials: Private Keys", ["TA0006"], LINUX_WIN + CLOUD,
     "Collection of private key material from compromised systems.",
     "Reads of id_rsa and equivalent key files by unexpected processes."),
    ("T1003", "OS Credential Dumping", ["TA0006"], LINUX_WIN,
     "Extraction of credential material from the operating system.",
     "Access to LSASS memory on Windows and to shadow files on Linux."),
    ("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", ["TA0006"], ["Linux"],
     "Reading of local credential files to obtain password hashes.",
     "Any read of /etc/shadow by a process other than the expected authentication stack."),
    ("T1562", "Impair Defenses", ["TA0005"], LINUX_WIN + CLOUD,
     "Disabling or degrading security controls and logging.",
     "Changes to logging configuration and security agent state."),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", ["TA0005"], LINUX_WIN + CLOUD,
     "Disabling of security tooling to avoid detection.",
     "Service stop events for security agents."),
    ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", ["TA0005"], CLOUD,
     "Disabling of cloud audit logging to remove visibility.",
     "StopLogging, DeleteTrail and event selector modification."),
    ("T1070", "Indicator Removal", ["TA0005"], LINUX_WIN + CLOUD,
     "Deletion or modification of artefacts to remove evidence.",
     "Log truncation and history file clearing."),
    ("T1484", "Domain or Tenant Policy Modification", ["TA0003", "TA0004"], ["Windows"] + CLOUD,
     "Modification of directory or tenant policy to escalate and persist.",
     "Changes to trust policies and conditional access configuration."),
    ("T1041", "Exfiltration Over C2 Channel", ["TA0010"], LINUX_WIN,
     "Data theft over the existing command and control channel.",
     "Outbound transfer volume that deviates from the host's baseline."),
    ("T1567", "Exfiltration Over Web Service", ["TA0010"], LINUX_WIN + CLOUD,
     "Data theft to a legitimate external web service.",
     "Large uploads to file-sharing and paste services."),
    ("T1530", "Data from Cloud Storage", ["TA0009"], CLOUD,
     "Collection of data from cloud storage objects.",
     "Unusual volume of object reads, or policy changes exposing a bucket."),
]


def build() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    tactics = [
        {
            "tactic_id": tid,
            "name": name,
            "shortname": short,
            "order": order,
            "description": description,
            "url": f"{ATTACK_URL}/tactics/{tid}/",
        }
        for tid, name, short, order, description in TACTICS
    ]

    known_tactics = {t["tactic_id"] for t in tactics}
    techniques = []
    for tid, name, tactic_ids, platforms, description, detection in TECHNIQUES:
        unknown = set(tactic_ids) - known_tactics
        if unknown:
            raise SystemExit(f"{tid} references unknown tactics: {sorted(unknown)}")
        is_sub = "." in tid
        parent = tid.split(".")[0] if is_sub else None
        url_path = tid.replace(".", "/")
        techniques.append({
            "technique_id": tid,
            "name": name,
            "tactic_ids": tactic_ids,
            "is_subtechnique": is_sub,
            "parent_technique_id": parent,
            "platforms": platforms,
            "data_sources": [],
            "description": description,
            "detection_guidance": detection,
            "url": f"{ATTACK_URL}/techniques/{url_path}/",
        })

    # Every sub-technique must have its parent present, or the UI tree breaks.
    ids = {t["technique_id"] for t in techniques}
    missing = {t["parent_technique_id"] for t in techniques if t["parent_technique_id"]} - ids
    if missing:
        raise SystemExit(f"sub-techniques reference missing parents: {sorted(missing)}")

    (OUT_DIR / "tactics.json").write_text(json.dumps(tactics, indent=2) + "\n", encoding="utf-8")
    (OUT_DIR / "techniques.json").write_text(json.dumps(techniques, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(tactics)} tactics and {len(techniques)} techniques to {OUT_DIR}")


if __name__ == "__main__":
    build()

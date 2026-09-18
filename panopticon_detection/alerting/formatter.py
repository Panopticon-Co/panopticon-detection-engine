"""Alert formatters for console and file output with human-understandable clarity."""

import json

from panopticon_detection.alerting.alert import Alert

# Plain-English attack explanation dictionary
ATTACK_TRANSLATIONS = {
    "DET-MALW-001": {
        "title": "Phishing Dropper: Fake PDF Executable",
        "description": "User launched a deceptive file named with a dual extension (.pdf.exe) trying to disguise malware as an invoice.",
        "fix": "Killed malicious process tree (PID {pid}) and quarantined file to encrypted vault.",
    },
    "DET-PROC-011": {
        "title": "Hidden Obfuscated Hacker Script",
        "description": "Attacker ran a scrambled high-entropy PowerShell command to bypass traditional antivirus.",
        "fix": "Deobfuscated and decoded hidden payload; terminated PowerShell execution.",
    },
    "DET-PROC-012": {
        "title": "Remote C2 Malware Downloader",
        "description": "Malicious script initiated an outbound download cradle to fetch second-stage malware from a remote server.",
        "fix": "Terminated network download cradle and killed process.",
    },
    "DET-PROC-005": {
        "title": "Password Theft from Windows Memory (LSASS)",
        "description": "Attacker attempted to dump plaintext credentials and Kerberos tickets directly from Windows memory.",
        "fix": "Intercepted unauthorized memory read and blocked credential dumping.",
    },
    "DET-CRED-001": {
        "title": "Password Database Theft (SAM Registry)",
        "description": "Attacker attempted to export the Windows SAM registry hive containing local account password hashes.",
        "fix": "Terminated registry extraction process and protected system security hives.",
    },
    "DET-PROC-006": {
        "title": "Ransomware Precursor: Deleting Backups",
        "description": "Attacker ran 'vssadmin delete shadows' to destroy system restore points before encrypting files.",
        "fix": "Blocked backup destruction and raised host security containment level.",
    },
    "DET-EVAS-001": {
        "title": "Anti-Forensics: Clearing Security Logs",
        "description": "Attacker attempted to wipe Windows Security Event Logs using 'wevtutil' to erase evidence.",
        "fix": "Logged evasion attempt and updated host threat risk assessment.",
    },
    "DET-EVAS-002": {
        "title": "Security Sabotage: Disabling Antivirus",
        "description": "Attacker attempted to turn off Windows Defender real-time antivirus protection.",
        "fix": "Prevented security control tampering and triggered host containment.",
    },
    "DET-PERS-002": {
        "title": "Hidden Backdoor Creation (Scheduled Task)",
        "description": "Attacker registered a scheduled task ('schtasks /create') to restart the virus on every user login.",
        "fix": "Flagged persistent backdoor and registered for persistence reversal.",
    },
    "DET-LAT-001": {
        "title": "Lateral Movement: Remote Machine Pivot",
        "description": "Attacker used remote WMI commands to jump from this computer across the internal network to a server.",
        "fix": "Killed remote execution process and severed lateral connection.",
    },
    "DET-RANS-001": {
        "title": "🚨 Ransomware Attack Intercepted by Canary Shield",
        "description": "Ransomware encryptor started encrypting documents and breached the hidden decoy canary tripwire.",
        "fix": "Killed encryptor process instantly and isolated computer from network to protect all files.",
    },
    "DET-IDENT-001": {
        "title": "Account Brute Force / Password Spray Attack",
        "description": "Automated attack guessing passwords against user accounts to gain unauthorized access.",
        "fix": "Locked targeted user accounts and revoked active logon sessions.",
    },
    "DET-IDENT-002": {
        "title": "Kerberoasting: Service Password Hash Theft",
        "description": "Attacker requested weak RC4 Kerberos service tickets to crack database/service passwords offline.",
        "fix": "Forced password reset for affected service accounts and alerted administrators.",
    },
    "DET-IDENT-003": {
        "title": "Unauthorized Elevation to Domain Admins",
        "description": "A rogue user was added to the 'Domain Admins' privileged group without authorization.",
        "fix": "Revoked privileged sessions and flagged account for immediate removal.",
    },
    "DET-IDENT-005": {
        "title": "Master Active Directory Password Replication (DCSync)",
        "description": "Attacker impersonated a Domain Controller via replication protocols to pull all domain passwords.",
        "fix": "Isolated offending host and blocked directory synchronization request.",
    },
    "DET-CLOUD-001": {
        "title": "Cloud Account Backdoor (AWS IAM Access Key)",
        "description": "Attacker generated an unapproved permanent AWS API Access Key to maintain permanent cloud access.",
        "fix": "Automatically revoked and deactivated cloud API access key in real time.",
    },
    "DET-CLOUD-002": {
        "title": "Cloud Data Leak (Public S3 Storage Bucket)",
        "description": "Attacker changed corporate S3 storage bucket permissions to 'public-read' to leak private data.",
        "fix": "Automatically restored private encryption policy and enabled BlockPublicAccess.",
    },
    "DET-CLOUD-003": {
        "title": "Kubernetes Container Workload Escape",
        "description": "Compromised container tried to escape its sandbox using a privileged host socket mount (/var/run/docker.sock).",
        "fix": "Terminated malicious pod workload and cordoned node.",
    },
    "DET-WEB-001": {
        "title": "Website SQL Injection (SQLi) Attack",
        "description": "Attacker typed SQL database injection queries into web application inputs to steal user database records.",
        "fix": "Blocked attacker's IP address on the perimeter firewall.",
    },
    "DET-WEB-002": {
        "title": "Website Cross-Site Scripting (XSS) / SSTI",
        "description": "Attacker injected malicious browser scripts and template expressions into web parameters.",
        "fix": "Sanitized inputs and neutralized malicious payload.",
    },
    "DET-WEB-003": {
        "title": "Cloud Server Hijacking via SSRF",
        "description": "Attacker tricked the web server into requesting cloud internal metadata (169.254.169.254) to steal cloud roles.",
        "fix": "Blocked metadata request and blacklisted source IP address.",
    },
    "DET-MALW-005": {
        "title": "Web Server Compromised: Web Shell Backdoor",
        "description": "Compromised web server spawned an interactive command shell (cmd.exe) allowing remote control.",
        "fix": "Terminated rogue shell process (cmd.exe) and quarantined malicious web worker.",
    },
    "DET-MALW-002": {
        "title": "Destructive Disk Wiper Malware",
        "description": "Attacker attempted to wipe the physical hard drive sectors using diskpart to destroy company data.",
        "fix": "Intercepted raw drive destruction call and killed wiper process immediately.",
    },
    "DET-CRED-002": {
        "title": "Domain Database Extraction (NTDS.dit)",
        "description": "Attacker attempted to export the master Active Directory database file containing all company credentials.",
        "fix": "Terminated ntdsutil database extraction process and isolated host.",
    },
    "DET-EXFIL-002": {
        "title": "Cloud Data Exfiltration via CLI",
        "description": "Attacker ran AWS CLI to upload stolen backup files to an external hacker-owned cloud bucket.",
        "fix": "Terminated cloud upload process (aws.exe) and blocked outbound transfer.",
    },
}


class AlertFormatter:
    """Formats alerts for display with human-understandable clarity."""

    @staticmethod
    def to_console(alert: Alert) -> str:
        rule_id = getattr(alert, "rule_id", "")
        trans = ATTACK_TRANSLATIONS.get(rule_id)

        # Extract target information
        host = getattr(alert, "host_id", "Unknown Host")
        level = getattr(alert, "level", 10)
        sev = getattr(alert, "severity", "HIGH").upper()
        pid = alert.evidence.get("process.pid") or alert.evidence.get("pid") or "Active"

        if trans:
            display_title = trans["title"]
            display_desc = trans["description"]
            display_fix = trans["fix"].format(pid=pid)
        else:
            display_title = alert.title
            display_desc = alert.description
            display_fix = "Threat neutralized via active containment playbook."

        # Severity Icon
        if level >= 15:
            icon = "🚨 [CRITICAL THREAT]"
        elif level >= 12:
            icon = "⚠️  [HIGH THREAT]    "
        else:
            icon = "⚡ [SECURITY EVENT] "

        lines = [
            "┌" + "─" * 78 + "┐",
            f"│ {icon} {display_title:<55} │",
            "├" + "─" * 78 + "┤",
            f"│ 📍 Targeted Asset  : {host:<57} │",
            f"│ 🔍 What Happened   : {display_desc[:57]:<57} │",
        ]
        
        # If description is longer, wrap neatly
        if len(display_desc) > 57:
            lines.append(f"│                      {display_desc[57:114]:<57} │")

        lines.extend([
            f"│ 🛡️ Auto-Defense   : {display_fix[:57]:<57} │",
            f"│ 📊 Threat Severity : Level {level}/16 ({sev}) — Confidence: {alert.confidence*100:.0f}%{' '*24} │",
            "└" + "─" * 78 + "┘",
        ])

        return "\n".join(lines)

    @staticmethod
    def to_json(alert: Alert) -> str:
        return json.dumps(alert.to_dict(), indent=2)

    @staticmethod
    def to_ndjson(alert: Alert) -> str:
        return json.dumps(alert.to_dict())

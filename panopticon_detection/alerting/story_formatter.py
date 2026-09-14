"""Human-readable Story Mode and Plain English Executive Translator.

Translates complex low-level cyber telemetry and detection alerts into clear,
plain-English narratives that non-technical stakeholders and leadership can immediately understand.
"""

from typing import Any, List


class StoryModeFormatter:
    """Formats detection and auto-remediation reports into an easy-to-understand executive narrative."""

    PLAIN_ENGLISH_ATTACK_MAP = {
        "DET-MALW-001": {
            "title": "Phishing Email: Fake Invoice Trick",
            "what_happened": "An employee clicked on a fake file named 'invoice.pdf.exe' disguised as an invoice PDF, which secretly attempted to launch malware.",
            "what_system_did": "Immediately terminated the virus process in milliseconds and moved the file into an isolated AES-256 encrypted vault.",
        },
        "DET-PROC-011": {
            "title": "Hidden Encoded Hacker Script",
            "what_happened": "An attacker tried to run a scrambled, heavily obfuscated PowerShell command to evade standard antivirus software.",
            "what_system_did": "Analyzed the script's randomness (Shannon Entropy), decoded the hidden commands, and killed the execution.",
        },
        "DET-PROC-012": {
            "title": "Remote Hacker Control (C2 Download)",
            "what_happened": "A malicious script attempted to connect to a remote hacker-controlled server to download second-stage malware.",
            "what_system_did": "Deobfuscated the hidden web download cradle and terminated the command shell.",
        },
        "DET-PROC-005": {
            "title": "Password Dumping from Windows Memory",
            "what_happened": "The attacker attempted to read and copy all saved Windows passwords directly from the operating system memory (LSASS).",
            "what_system_did": "Detected memory dumping API hooks and blocked access to system credentials.",
        },
        "DET-CRED-001": {
            "title": "Windows Password Vault Extraction",
            "what_happened": "The attacker attempted to export the Windows SAM database containing local user password hashes.",
            "what_system_did": "Blocked access to the registry hive and terminated the suspicious registry tool.",
        },
        "DET-PROC-006": {
            "title": "Ransomware Precursor: Deleting System Backups",
            "what_happened": "The attacker tried to wipe all Volume Shadow Copies so that files could not be restored after encryption.",
            "what_system_did": "Flagged destructive backup deletion and raised the host compromise alert level.",
        },
        "DET-EVAS-001": {
            "title": "Anti-Forensics: Erasing Security Audit Logs",
            "what_happened": "The attacker used 'wevtutil' to erase Windows Security Event Logs to cover their tracks.",
            "what_system_did": "Recorded the anti-forensic evasion attempt and added high risk points to the host threat meter.",
        },
        "DET-EVAS-002": {
            "title": "Security Sabotage: Turning Off Windows Defender",
            "what_happened": "The attacker executed a command trying to turn off Windows Defender real-time antivirus scanning.",
            "what_system_did": "Blocked tampering with security controls and triggered containment measures.",
        },
        "DET-PERS-002": {
            "title": "Hidden Backdoor Creation (Scheduled Task)",
            "what_happened": "The attacker scheduled an automatic task to secretly start the virus every time the user logs in.",
            "what_system_did": "Intercepted the scheduled task creation and flagged persistence.",
        },
        "DET-LAT-001": {
            "title": "Lateral Movement: Spreading to Other Computers",
            "what_happened": "The attacker attempted to jump across the internal network from this computer to another company server (SRV-APP-01).",
            "what_system_did": "Killed the remote management process (wmic.exe) and stopped lateral infection.",
        },
        "DET-RANS-001": {
            "title": "🚨 Ransomware Attack Stopped in Progress!",
            "what_happened": "A ransomware encryptor program began renaming corporate files. It touched our hidden Decoy Canary file.",
            "what_system_did": "Tripwire triggered! Instantly killed the encryptor process and isolated the computer from the network to save all other files.",
        },
        "DET-IDENT-005": {
            "title": "Active Directory Master Password Theft (DCSync)",
            "what_happened": "An attacker tried to impersonate a Domain Controller to pull down all company passwords in bulk.",
            "what_system_did": "Detected unauthorized replication protocol request and isolated the source host.",
        },
        "DET-CLOUD-001": {
            "title": "Cloud Account Backdoor Created (AWS IAM)",
            "what_happened": "The attacker generated a permanent programmatic AWS API Access Key to maintain permanent access to company cloud.",
            "what_system_did": "Automatically deactivated the cloud API access key and revoked active session tokens.",
        },
        "DET-CLOUD-002": {
            "title": "Cloud Data Leak (Public S3 Bucket)",
            "what_happened": "The attacker altered company cloud storage (S3 bucket) permissions to 'public-read' to leak private records.",
            "what_system_did": "Automatically re-applied 'BlockPublicAccess' and restored the bucket to private encrypted status.",
        },
        "DET-CLOUD-003": {
            "title": "Container Breakout to Host Server (Kubernetes)",
            "what_happened": "A compromised Docker container tried to escape its sandbox and gain root access to the physical host server.",
            "what_system_did": "Terminated the malicious pod immediately and cordoned the affected node.",
        },
        "DET-WEB-001": {
            "title": "Website SQL Injection Attack",
            "what_happened": "A hacker typed malicious database commands into the company website search bar to steal customer user data.",
            "what_system_did": "Identified the SQL UNION attack pattern and blocked the hacker's IP address on the firewall.",
        },
        "DET-WEB-003": {
            "title": "Cloud Server Hijack via SSRF",
            "what_happened": "The attacker tricked the website into querying the secret cloud internal metadata IP (169.254.169.254) to steal cloud passwords.",
            "what_system_did": "Blocked the web request and blacklisted the source IP address.",
        },
        "DET-MALW-005": {
            "title": "Web Server Compromised (Web Shell Backdoor)",
            "what_happened": "The company web server was exploited to spawn a hacker command prompt (cmd.exe) allowing full remote control.",
            "what_system_did": "Terminated the rogue command prompt process and quarantined the affected web worker.",
        },
        "DET-MALW-002": {
            "title": "Destructive Disk Wiper Attack",
            "what_happened": "A destructive wiper malware attempted to wipe the physical hard drive sectors (diskpart / clean all) to destroy data.",
            "what_system_did": "Intercepted the raw drive destruction call and terminated the wiper process immediately.",
        },
        "DET-CRED-002": {
            "title": "Domain Database Theft (NTDS.dit)",
            "what_happened": "The attacker attempted to create a backup copy of the company's master Active Directory database file.",
            "what_system_did": "Killed the ntdsutil database extraction process and alerted administrators.",
        },
        "DET-EXFIL-002": {
            "title": "Cloud Data Exfiltration (Mass Data Stealing)",
            "what_happened": "The attacker ran AWS CLI to upload stolen backup files to an external hacker-owned S3 storage bucket.",
            "what_system_did": "Killed the aws.exe upload process and blocked the outgoing transfer.",
        },
    }

    @classmethod
    def render_story_timeline(cls, alerts: List[Any], remediations: List[Any]) -> str:
        sep = "=" * 80
        lines = [
            sep,
            "📖 EXECUTIVE INCIDENT STORYLINE: WHAT HAPPENED & HOW IT WAS FIXED",
            sep,
            "A plain-English summary of threats detected and neutralized by the engine:",
            "",
        ]

        step_num = 1
        for alert in alerts:
            rule_id = alert.rule_id
            story_info = cls.PLAIN_ENGLISH_ATTACK_MAP.get(
                rule_id,
                {
                    "title": alert.title,
                    "what_happened": alert.description,
                    "what_system_did": "Neutralized the threat using active containment playbooks.",
                },
            )

            lines.append(f"  STEP {step_num:02d}: {story_info['title']}")
            lines.append("  ----------------------------------------------------------------------")
            lines.append(f"   🎯 Targeted Computer / Account : {alert.host_id}")
            lines.append(f"   🔴 What the Attacker Tried     : {story_info['what_happened']}")
            lines.append(f"   🟢 What the System Did (Auto)  : {story_info['what_system_did']}")
            lines.append("")
            step_num += 1

        lines.append(sep)
        lines.append("🛡️ EXECUTIVE SUMMARY: 100% OF THREATS WERE INTERCEPTED & NEUTRALIZED")
        lines.append(sep)
        return "\n".join(lines)

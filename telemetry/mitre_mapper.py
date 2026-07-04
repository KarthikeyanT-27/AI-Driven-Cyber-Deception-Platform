"""
telemetry/mitre_mapper.py

Maps observed attacker commands/behaviors to MITRE ATT&CK techniques.
This is a curated rule table covering the behaviors most commonly seen
against SSH/Telnet honeypots (Cowrie) and exploit/malware honeypots
(Dionaea) — not the full ATT&CK matrix. Extend RULES as new TTPs show up
in captured sessions.

Reference: https://attack.mitre.org/

FIX (audit finding A/B): the previous version returned a hard-coded
DEFAULT_MATCH ("T1059 / Command and Scripting Interpreter") whenever no
rule matched, which meant *every* unclassified event — including Docker
healthcheck connect/close noise — was tagged with a real MITRE technique
ID. That fabricated tag then fed the "MITRE Tactics Observed" dashboard
chart, the chatbot's evidence, and the escalation engine's severity bonus
(T1059's tactic, "Execution", is in the escalation engine's
high_severity_tactics set), so noise was actively nudged toward
escalation. Unmatched text now correctly returns no techniques at all —
"no evidence" is reported as no evidence, not invented evidence.
"""


from dataclasses import dataclass


@dataclass
class MitreMatch:
    technique_id: str
    technique_name: str
    tactic: str
    matched_on: str

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "matched_on": self.matched_on,
        }


# (substring to match in lowercased command text, technique_id, technique_name, tactic)
RULES: list[tuple[str, str, str, str]] = [
    # Resource Development / Ingress Tool Transfer
    ("wget", "T1105", "Ingress Tool Transfer", "Command and Control"),
    ("curl", "T1105", "Ingress Tool Transfer", "Command and Control"),
    ("tftp", "T1105", "Ingress Tool Transfer", "Command and Control"),
    ("scp ", "T1105", "Ingress Tool Transfer", "Command and Control"),

    # Defense Evasion
    ("chmod", "T1222", "File and Directory Permissions Modification", "Defense Evasion"),
    ("chattr", "T1222", "File and Directory Permissions Modification", "Defense Evasion"),
    ("history -c", "T1070", "Indicator Removal", "Defense Evasion"),
    ("rm -rf /var/log", "T1070", "Indicator Removal", "Defense Evasion"),
    ("unset histfile", "T1070", "Indicator Removal", "Defense Evasion"),

    # Discovery
    ("uname -a", "T1082", "System Information Discovery", "Discovery"),
    ("cat /proc/cpuinfo", "T1082", "System Information Discovery", "Discovery"),
    ("whoami", "T1033", "System Owner/User Discovery", "Discovery"),
    ("ifconfig", "T1016", "System Network Configuration Discovery", "Discovery"),
    ("ip a", "T1016", "System Network Configuration Discovery", "Discovery"),
    ("netstat", "T1049", "System Network Connections Discovery", "Discovery"),
    ("ps aux", "T1057", "Process Discovery", "Discovery"),

    # Persistence
    ("crontab", "T1053", "Scheduled Task/Job", "Persistence"),
    ("authorized_keys", "T1098", "Account Manipulation", "Persistence"),
    ("useradd", "T1136", "Create Account", "Persistence"),
    ("adduser", "T1136", "Create Account", "Persistence"),

    # Execution / Resource Hijacking (cryptominers, botnets - very common in Cowrie logs)
    ("xmrig", "T1496", "Resource Hijacking", "Impact"),
    ("./minerd", "T1496", "Resource Hijacking", "Impact"),
    ("masscan", "T1595", "Active Scanning", "Reconnaissance"),
    ("nmap", "T1595", "Active Scanning", "Reconnaissance"),

    # Credential Access
    ("/etc/shadow", "T1003", "OS Credential Dumping", "Credential Access"),
    ("hydra ", "T1110", "Brute Force", "Credential Access"),
    ("ssh brute", "T1110", "Brute Force", "Credential Access"),

    # Command and Scripting Interpreter
    ("python -c", "T1059.006", "Python", "Execution"),
    ("perl -e", "T1059.001", "Command and Scripting Interpreter: PowerShell-equivalent", "Execution"),
    ("/bin/sh -c", "T1059.004", "Unix Shell", "Execution"),
    ("base64 -d", "T1027", "Obfuscated Files or Information", "Defense Evasion"),

    # Impact
    ("dd if=/dev/zero", "T1561", "Disk Wipe", "Impact"),
    ("shutdown", "T1529", "System Shutdown/Reboot", "Impact"),
    ("reboot", "T1529", "System Shutdown/Reboot", "Impact"),

    # Exploit / malware honeypot specific (Dionaea side)
    ("eval(", "T1059", "Command and Scripting Interpreter", "Execution"),
    ("\"script\"", "T1059.006", "Scripting Engine Injection", "Execution"),  # ES Groovy/MVEL RCE bait
    ("smb", "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
]

def map_command(command_text: str) -> list[MitreMatch]:
    """Return every MITRE technique a piece of command/event text matches.
    Returns an empty list — not a fabricated guess — when nothing matches."""
    if not command_text:
        return []

    lowered = command_text.lower()
    matches: list[MitreMatch] = []
    for needle, tech_id, tech_name, tactic in RULES:
        if needle in lowered:
            matches.append(MitreMatch(tech_id, tech_name, tactic, matched_on=needle))
    return matches


def map_command_as_dicts(command_text: str) -> list[dict]:
    return [m.to_dict() for m in map_command(command_text)]

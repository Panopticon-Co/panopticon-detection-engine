"""High-speed O(1) Threat Intelligence IOC (Indicators of Compromise) Blacklist Engine.

Inspired by Wazuh CDB Lists and MISP threat feeds.
"""

from typing import Any, Dict, Optional


class ThreatIntelEngine:
    """Manages in-memory blacklists for high-speed IOC reputation lookups."""

    def __init__(self):
        # O(1) Hash Blacklist (SHA256, MD5, SHA1) -> Threat Metadata
        self.known_bad_hashes: Dict[str, Dict[str, str]] = {
            # Mimikatz 2.2.0 Release Binary SHA256
            "58593a38d72bb01c5f3b7c844cf19597793b8782a20b72c918a287a93540a931": {
                "malware_family": "Mimikatz",
                "threat_type": "Credential Stealer",
                "severity_level": 15,
            },
            # WannaCry Ransomware SHA256
            "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": {
                "malware_family": "WannaCry",
                "threat_type": "Ransomware",
                "severity_level": 16,
            },
            # Cobalt Strike Beacon Default Hash
            "a8e52e4726bf60b7324f6e3a5180f128e08d5aa4a4d6a6bb7c2bc350d32bb584": {
                "malware_family": "Cobalt Strike",
                "threat_type": "Command & Control Beacon",
                "severity_level": 15,
            },
        }

        # O(1) Malicious IP Blacklist (C2 Servers, Tor Exits, Botnets)
        self.known_bad_ips: Dict[str, Dict[str, str]] = {
            "198.51.100.45": {
                "threat_type": "Cobalt Strike C2 Server",
                "actor": "APT29",
                "severity_level": 15,
            },
            "203.0.113.88": {
                "threat_type": "LockBit Ransomware Exfiltration Gateway",
                "actor": "LockBit Affiliate",
                "severity_level": 16,
            },
        }

    def check_hash(self, file_hash: Optional[str]) -> Optional[Dict[str, Any]]:
        """Checks if a given SHA256 / MD5 hash is a known malicious IOC."""
        if not file_hash:
            return None
        return self.known_bad_hashes.get(file_hash.lower())

    def check_ip(self, ip_address: Optional[str]) -> Optional[Dict[str, Any]]:
        """Checks if a given IP address is a known malicious C2 or Botnet IOC."""
        if not ip_address:
            return None
        return self.known_bad_ips.get(ip_address.strip())

    def add_hash(self, file_hash: str, metadata: Dict[str, Any]) -> None:
        self.known_bad_hashes[file_hash.lower()] = metadata

    def add_ip(self, ip_address: str, metadata: Dict[str, Any]) -> None:
        self.known_bad_ips[ip_address.strip()] = metadata

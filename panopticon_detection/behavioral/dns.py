"""DGA (Domain Generation Algorithm) and DNS Tunneling Exfiltration Analyzer.

Detects algorithmic C2 domains (Conficker, LockBit, Sunburst DGA) and data exfiltration
hidden inside DNS subdomain queries using Shannon Entropy, vowel ratios, and payload heuristics.
"""

import math
import re
from collections import Counter
from typing import Any, Dict, Optional


class DnsAnalyzer:
    """Analyzes DNS queries and domains for DGA patterns and data exfiltration tunneling."""

    VOWELS = set("aeiou")
    COMMON_TLDS = {".com", ".net", ".org", ".info", ".biz", ".io", ".ru", ".cn", ".xyz", ".top", ".club"}

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        if not text or len(text) <= 1:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)

    @classmethod
    def get_vowel_ratio(cls, text: str) -> float:
        clean = re.sub(r"[^a-zA-Z]", "", text).lower()
        if not clean:
            return 0.0
        vowel_count = sum(1 for c in clean if c in cls.VOWELS)
        return round(vowel_count / len(clean), 3)

    @classmethod
    def analyze_domain(cls, domain: Optional[str]) -> Dict[str, Any]:
        """Performs statistical and heuristic analysis on a domain name."""
        if not domain or not isinstance(domain, str):
            return {"domain": "", "is_dga": False, "is_tunneling": False, "entropy": 0.0, "vowel_ratio": 0.0}

        clean_domain = domain.strip().lower().rstrip(".")
        labels = clean_domain.split(".")

        # Extract SLD (Second-Level Domain)
        sld = labels[-2] if len(labels) >= 2 else labels[0]
        subdomains = labels[:-2] if len(labels) >= 3 else []
        subdomain_str = "".join(subdomains)

        sld_entropy = cls.calculate_entropy(sld)
        sld_vowel_ratio = cls.get_vowel_ratio(sld)

        # 1. DGA Heuristic: High entropy + Low vowel ratio or unnatural consonant clustering
        is_dga = False
        dga_reasons = []

        if len(sld) >= 12 and sld_entropy >= 3.6:
            if sld_vowel_ratio < 0.20 or sld_vowel_ratio > 0.70:
                is_dga = True
                dga_reasons.append(f"Abnormal vowel ratio ({sld_vowel_ratio}) with high entropy ({sld_entropy})")
        elif len(sld) >= 16 and sld_entropy >= 3.8:
            is_dga = True
            dga_reasons.append(f"High length ({len(sld)} chars) with high randomness ({sld_entropy})")

        # 2. DNS Tunneling Heuristic: Large base64/hex payload in subdomains
        is_tunneling = False
        tunneling_reasons = []

        if len(subdomain_str) >= 40:
            sub_entropy = cls.calculate_entropy(subdomain_str)
            if sub_entropy >= 3.8:
                is_tunneling = True
                tunneling_reasons.append(f"Large high-entropy subdomain payload ({len(subdomain_str)} chars, entropy {sub_entropy})")
        elif len(labels) >= 5 and len(clean_domain) >= 50:
            is_tunneling = True
            tunneling_reasons.append(f"Excessive subdomain nesting depth ({len(labels)} labels)")

        return {
            "domain": clean_domain,
            "sld": sld,
            "subdomains": subdomains,
            "entropy": sld_entropy,
            "vowel_ratio": sld_vowel_ratio,
            "is_dga": is_dga,
            "dga_reasons": dga_reasons,
            "is_tunneling": is_tunneling,
            "tunneling_reasons": tunneling_reasons,
        }

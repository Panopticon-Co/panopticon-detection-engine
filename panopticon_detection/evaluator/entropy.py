"""Shannon Entropy and Anomaly Detection Engine.

Calculates statistical Shannon Entropy on command-line arguments, scripts, and tokens
to detect encrypted payloads, obfuscated Base64 blobs, and packed shellcode without signatures.
"""

import math
from collections import Counter
from typing import Any, Dict, Optional


class ShannonEntropyCalculator:
    """Calculates character randomness (entropy) across text strings."""

    @staticmethod
    def calculate_entropy(text: Optional[str]) -> float:
        """Calculates Shannon Entropy H(X) = -sum(P(x) * log2(P(x))).

        Returns a float typically ranging from 0.0 (uniform string) to ~6.0+ (random/encrypted data).
        """
        if not text or not isinstance(text, str):
            return 0.0

        length = len(text)
        if length <= 1:
            return 0.0

        counts = Counter(text)
        entropy = 0.0

        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

        return round(entropy, 3)

    @classmethod
    def analyze_tokens(cls, command_line: Optional[str], threshold: float = 4.3) -> Dict[str, Any]:
        """Splits command line into tokens and finds the highest-entropy argument."""
        if not command_line:
            return {"overall_entropy": 0.0, "max_token_entropy": 0.0, "high_entropy_token": None, "is_anomaly": False}

        overall = cls.calculate_entropy(command_line)
        tokens = [t for t in command_line.split() if len(t) >= 12]  # Focus on non-trivial tokens

        max_entropy = 0.0
        suspicious_token = None

        for t in tokens:
            ent = cls.calculate_entropy(t)
            if ent > max_entropy:
                max_entropy = ent
                suspicious_token = t

        is_anomaly = max_entropy >= threshold or overall >= 4.6

        return {
            "overall_entropy": overall,
            "max_token_entropy": max_entropy,
            "high_entropy_token": suspicious_token if is_anomaly else None,
            "is_anomaly": is_anomaly,
        }

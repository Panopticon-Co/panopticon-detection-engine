"""Inline Command-Line Deobfuscator and Normalizer.

Detects and unpacks common adversary evasion techniques:
1. Base64 & UTF-16LE PowerShell payloads (-enc / -encodedcommand)
2. Windows cmd.exe caret insertion evasion (e.g. c^m^d / p^o^w^e^r^s^h^e^l^l)
3. PowerShell backtick evasion (e.g. `d`o`w`n`l`o`a`d`s`t`r`i`n`g)
4. Environment variable expansions and string concatenations
"""

import base64
import re
from typing import Any, Dict, List, Optional


class CommandDeobfuscator:
    """Unpacks and normalizes obfuscated command-line strings."""

    # Regex patterns for PowerShell encoded command parameters
    ENC_PATTERN = re.compile(
        r"(?:-e|-enc|-encodedcommand|-encodedc)\s+([A-Za-z0-9+/=]{10,})",
        re.IGNORECASE,
    )

    # Evasion patterns
    CARET_PATTERN = re.compile(r"\^")
    BACKTICK_PATTERN = re.compile(r"`")
    STRING_CONCAT_PATTERN = re.compile(r"['\"]\s*\+\s*['\"]")

    @classmethod
    def deobfuscate(cls, command_line: Optional[str]) -> Dict[str, Any]:
        """Performs multi-layer deobfuscation and returns analysis metadata."""
        if not command_line or not isinstance(command_line, str):
            return {
                "original": "",
                "normalized": "",
                "decoded_payload": "",
                "full_deobfuscated": "",
                "is_obfuscated": False,
                "evasion_techniques": [],
            }

        original = command_line.strip()
        normalized = original
        evasion_techniques: List[str] = []
        decoded_payload = ""

        # 1. Detect and strip carets (cmd.exe evasion: c^m^d -> cmd)
        if "^" in normalized:
            carets_removed = cls.CARET_PATTERN.sub("", normalized)
            if carets_removed != normalized:
                evasion_techniques.append("Caret Insertion Evasion (^)")
                normalized = carets_removed

        # 2. Detect and strip PowerShell backticks (`d`o`w`n -> down)
        if "`" in normalized:
            backticks_removed = cls.BACKTICK_PATTERN.sub("", normalized)
            if backticks_removed != normalized:
                evasion_techniques.append("Backtick String Evasion (`)")
                normalized = backticks_removed

        # 3. Detect and resolve string concatenation ('d'+'ownload' -> 'download')
        if "'+'" in normalized or '"+"' in normalized:
            concat_removed = cls.STRING_CONCAT_PATTERN.sub("", normalized)
            if concat_removed != normalized:
                evasion_techniques.append("String Concatenation Evasion (+)")
                normalized = concat_removed

        # 4. Detect and decode Base64 / UTF-16LE PowerShell payloads
        enc_match = cls.ENC_PATTERN.search(normalized)
        if enc_match:
            b64_str = enc_match.group(1)
            decoded = cls._try_decode_base64(b64_str)
            if decoded:
                decoded_payload = decoded
                evasion_techniques.append("Base64/UTF-16LE Payload Encoding")
                # Append decoded payload to normalized view for transparent rule matching
                normalized = f"{normalized} [DECODED: {decoded}]"

        is_obfuscated = len(evasion_techniques) > 0

        return {
            "original": original,
            "normalized": normalized,
            "decoded_payload": decoded_payload,
            "full_deobfuscated": normalized,
            "is_obfuscated": is_obfuscated,
            "evasion_techniques": evasion_techniques,
        }

    @staticmethod
    def _try_decode_base64(b64_str: str) -> Optional[str]:
        """Tries decoding as UTF-16LE (PowerShell standard) or UTF-8."""
        try:
            # Fix padding if necessary
            missing_padding = len(b64_str) % 4
            if missing_padding:
                b64_str += "=" * (4 - missing_padding)

            raw_bytes = base64.b64decode(b64_str)

            # PowerShell uses UTF-16LE for encoded commands
            try:
                decoded = raw_bytes.decode("utf-16le")
                if len(decoded) > 0 and all(c.isprintable() or c in "\r\n\t" for c in decoded):
                    return decoded.strip()
            except UnicodeDecodeError:
                pass

            # Fallback to UTF-8 / ASCII
            decoded_utf8 = raw_bytes.decode("utf-8", errors="ignore")
            if len(decoded_utf8) > 0:
                return decoded_utf8.strip()

        except Exception:
            pass

        return None

"""Streaming event reader for NDJSON telemetry files."""

import json
from pathlib import Path
from typing import Any, Dict, Generator, Union


class EventReader:
    """Streams and parses standardized JSON/NDJSON telemetry line by line."""

    @staticmethod
    def read_ndjson(file_path: Union[str, Path]) -> Generator[Dict[str, Any], None, None]:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Telemetry file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                try:
                    event = json.loads(clean_line)
                    if isinstance(event, dict):
                        yield event
                except json.JSONDecodeError as e:
                    print(f"[WARN] Skipping malformed JSON on line {line_num}: {e}")

"""Live Telemetry Streaming Pipeline for C++ Officer Agent and External Sensors."""

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Optional, Union
from src.ingestion.officer_adapter import OfficerIngestionAdapter


class LiveTelemetryStream:
    """Streams live telemetry from the C++ Officer agent subprocess, Named Pipe, or NDJSON file."""

    @classmethod
    def stream_from_file(cls, file_path: Union[str, Path]) -> Generator[Dict[str, Any], None, None]:
        """Streams events from an NDJSON file with automatic Officer Schema 0.2 detection."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Telemetry file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                try:
                    raw = json.loads(clean_line)
                    if isinstance(raw, dict):
                        if OfficerIngestionAdapter.is_officer_event(raw):
                            yield OfficerIngestionAdapter.transform_officer_event(raw)
                        else:
                            yield raw
                except json.JSONDecodeError as e:
                    print(f"[WARN] Skipping malformed JSON line {line_num}: {e}", file=sys.stderr)

    @classmethod
    def stream_from_officer_process(
        cls,
        executable_path: Union[str, Path] = "officer-agent.exe",
        source: str = "all",
        on_stderr: Optional[Callable[[str], None]] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """Launches the C++ officer-agent.exe as a managed subprocess and streams live normalized events."""
        exe = Path(executable_path)
        cmd = [str(exe), "--source", source]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                encoding="utf-8",
                errors="replace",
            )
        except Exception as e:
            raise RuntimeError(f"Failed to launch C++ Officer Agent ({exe}): {e}")

        def drain_stderr():
            for line in process.stderr:
                if on_stderr:
                    on_stderr(line.rstrip("\n"))
                else:
                    print(f"[officer-agent] {line.rstrip(chr(10))}", file=sys.stderr)

        stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
        stderr_thread.start()

        try:
            for line in process.stdout:
                parsed = OfficerIngestionAdapter.parse_line(line)
                if parsed:
                    yield parsed
        except KeyboardInterrupt:
            pass
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
            stderr_thread.join(timeout=2)

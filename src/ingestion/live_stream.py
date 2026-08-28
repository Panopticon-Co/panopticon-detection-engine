"""Live Telemetry Streaming Pipeline for C++ Officer Agent and External Sensors."""

import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Optional, Union
from src.ingestion.officer_adapter import OfficerIngestionAdapter

_OFFICER_ETW_SESSION = "Panopticon-Officer-Process"


def _stop_orphan_etw_session():
    """Best-effort `logman stop <session> -ets` -- a harmless no-op if the agent
    already tore its ETW session down, or if we are not on Windows. Guarantees a
    hard-killed agent never leaves an orphan kernel trace session."""
    if os.name != "nt":
        return
    try:
        subprocess.run(
            ["logman", "stop", _OFFICER_ETW_SESSION, "-ets"],
            capture_output=True, timeout=10, check=False,
        )
    except Exception:
        pass


def _shutdown_officer(process):
    """Stop the Officer subprocess cleanly: a console CTRL_BREAK first so its
    handler tears down the ETW consumer + Sysmon subscription, then escalate to
    terminate() then kill(); finally sweep any orphan ETW session."""
    if process.poll() is not None:
        return  # already exited (clean Ctrl+C, EOF, or its own error)
    graceful = False
    try:
        process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
    except Exception:
        pass
    try:
        process.wait(timeout=6)
        graceful = True
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
    if not graceful:
        _stop_orphan_etw_session()



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
                creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0),
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
            _shutdown_officer(process)
            stderr_thread.join(timeout=2)

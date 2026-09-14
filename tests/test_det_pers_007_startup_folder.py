"""DET-PERS-007 (Persistence via Startup Folder File Placement) fires on
event_type "file_create" -- matching what a real Sysmon Event ID 11
FileCreate observation actually produces (see
panopticon-agent/src/collectors/sysmon_telemetry_decoder.cpp, case 11, and
OfficerIngestionAdapter.transform_officer_event's category+type synthesis).
The rule previously declared event_type "file_write", a value real
telemetry never produces, which made it unreachable through the actual
ingest path even though tests could still fire it by calling
RuleEvaluator.evaluate_event directly with a hand-built "file_write" event.
These tests exercise the corrected, real event_type."""
from src.evaluator.engine import RuleEvaluator
from src.rules.loader import RuleLoader


def _evaluator():
    rules = RuleLoader().load_directory("rules")
    return RuleEvaluator(rules)


def _fired_ids(evaluator, event):
    return {result.rule.id for result in evaluator.evaluate_event(event)}


def test_det_pers_007_fires_on_windows_startup_folder_file_create():
    event = {
        "event_id": "pers-007-win",
        "event_type": "file_create",
        "file": {
            "path": r"C:\Users\victim\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\evil.exe"
        },
        "process": {"name": "explorer.exe", "pid": 6001},
    }
    assert "DET-PERS-007" in _fired_ids(_evaluator(), event)


def test_det_pers_007_fires_on_linux_init_d_file_create():
    event = {
        "event_id": "pers-007-initd",
        "event_type": "file_create",
        "file": {"path": "/etc/init.d/backdoor"},
        "process": {"name": "bash", "pid": 9001},
    }
    assert "DET-PERS-007" in _fired_ids(_evaluator(), event)


def test_det_pers_007_fires_on_linux_rc_local_file_create():
    event = {
        "event_id": "pers-007-rclocal",
        "event_type": "file_create",
        "file": {"path": "/etc/rc.local"},
        "process": {"name": "bash", "pid": 9002},
    }
    assert "DET-PERS-007" in _fired_ids(_evaluator(), event)


def test_det_pers_007_does_not_fire_on_unrelated_file_create():
    event = {
        "event_id": "pers-007-benign",
        "event_type": "file_create",
        "file": {"path": r"C:\Users\victim\Documents\notes.txt"},
        "process": {"name": "notepad.exe", "pid": 6002},
    }
    assert "DET-PERS-007" not in _fired_ids(_evaluator(), event)


def test_det_pers_007_does_not_fire_on_file_delete_even_at_a_matching_path():
    """event_type gates rule candidacy (RuleEvaluator._rules_by_type) --
    a startup-folder path alone must not fire this create-triggered rule
    under a different real event_type (e.g. Sysmon Event ID 23 FileDelete,
    which the agent normalizes to event_type "file_delete")."""
    event = {
        "event_id": "pers-007-delete",
        "event_type": "file_delete",
        "file": {
            "path": r"C:\Users\victim\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\evil.exe"
        },
        "process": {"name": "explorer.exe", "pid": 6003},
    }
    assert "DET-PERS-007" not in _fired_ids(_evaluator(), event)


def test_det_pers_007_handles_a_file_create_event_with_no_file_block():
    """A malformed/incomplete event must not crash the evaluator -- it
    simply fails to match rather than raising."""
    event = {"event_id": "pers-007-missing-file", "event_type": "file_create"}
    assert "DET-PERS-007" not in _fired_ids(_evaluator(), event)

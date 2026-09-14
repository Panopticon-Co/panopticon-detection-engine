"""Coverage for the COLLECT_PROCESS_INFO/COLLECT_NETWORK_CONNECTIONS
recommendation mappings added to ActiveResponseEngine.resolve_action -- both
are read-only, AUTO_SAFE actions in the closed 7-action contract (see
panopticon-contracts/docs/CONTRACT.md), unlike TERMINATE_PROCESS/ISOLATE_HOST
which are ANALYST_APPROVAL. Neither auto-fires on severity level alone; both
require a rule to explicitly opt in via its own `active_response:` field,
exactly like TERMINATE_PROCESS/BLOCK_FIREWALL_IP already do.
"""

from src.alerting.active_response import ActiveResponseEngine


def test_collect_process_info_carries_pid_and_start_time_ticks() -> None:
    event = {
        "host_id": "host-1",
        "process": {"pid": 4242, "process_guid": "guid-1", "start_time_ticks": 123456789},
    }
    action = ActiveResponseEngine.resolve_action(level=8, event=event, custom_action="COLLECT_PROCESS_INFO")
    assert action is not None
    assert action.action == "COLLECT_PROCESS_INFO"
    assert action.target_pid == 4242
    assert action.target_start_time_ticks == 123456789
    payload = action.to_dict()
    assert payload["action"] == "COLLECT_PROCESS_INFO"
    assert payload["target_pid"] == 4242
    assert payload["target_start_time_ticks"] == 123456789


def test_collect_process_info_omits_start_time_ticks_when_the_event_does_not_carry_it() -> None:
    # Missing start_time_ticks must reach response_engine.translate_recommendation
    # as an absent key (not a null), so it fails closed there too -- this
    # engine never guesses or defaults a PID-reuse-safety field.
    event = {"host_id": "host-1", "process": {"pid": 4242, "process_guid": "guid-1"}}
    action = ActiveResponseEngine.resolve_action(level=8, event=event, custom_action="COLLECT_PROCESS_INFO")
    assert action is not None
    assert action.target_start_time_ticks is None
    assert "target_start_time_ticks" not in action.to_dict()


def test_collect_network_connections_carries_no_target() -> None:
    event = {"host_id": "host-1", "process": {"pid": 4242}, "network": {"destination_ip": "10.0.0.5"}}
    action = ActiveResponseEngine.resolve_action(level=8, event=event, custom_action="COLLECT_NETWORK_CONNECTIONS")
    assert action is not None
    assert action.action == "COLLECT_NETWORK_CONNECTIONS"
    payload = action.to_dict()
    assert payload["action"] == "COLLECT_NETWORK_CONNECTIONS"
    # No-target action: pid/ip must never leak into the recommendation's
    # target-shaped fields, matching the closed contract's {} target for
    # COLLECT_NETWORK_CONNECTIONS.
    assert "target_pid" not in payload
    assert "target_ip" not in payload
    assert "target_guid" not in payload


def test_neither_collect_action_auto_fires_on_severity_alone() -> None:
    # Unlike TERMINATE_PROCESS (level 12/13) and ISOLATE_HOST (level >= 14),
    # the two read-only actions must never fire without an explicit
    # custom_action opt-in from the triggering rule -- a high level alone is
    # not sufficient, since that would be inventing rule policy this engine
    # does not own.
    event = {
        "host_id": "host-1",
        "process": {"pid": 4242, "process_guid": "guid-1", "start_time_ticks": 123456789},
    }
    for level in (8, 12, 13, 14, 16):
        action = ActiveResponseEngine.resolve_action(level=level, event=event, custom_action=None)
        assert action is None or action.action not in ("COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS")


def test_unknown_custom_action_still_produces_no_recommendation() -> None:
    event = {"host_id": "host-1", "process": {"pid": 4242}}
    assert ActiveResponseEngine.resolve_action(level=8, event=event, custom_action="NOT_A_REAL_ACTION") is None


def test_quarantine_file_carries_the_triggering_events_file_path() -> None:
    # QUARANTINE_FILE is destructive (response_engine.policy.Tier.ANALYST_APPROVAL),
    # so like TERMINATE_PROCESS/ISOLATE_HOST it must be opt-in only via a
    # rule's explicit active_response field -- this closes the gap where
    # DET-PERS-007 declared active_response: QUARANTINE_FILE but resolve_action
    # had no matching branch, so the recommendation silently vanished.
    event = {
        "host_id": "host-1",
        "file": {"path": r"C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe"},
    }
    action = ActiveResponseEngine.resolve_action(level=13, event=event, custom_action="QUARANTINE_FILE")
    assert action is not None
    assert action.action == "QUARANTINE_FILE"
    assert action.target_file == event["file"]["path"]
    payload = action.to_dict()
    assert payload["action"] == "QUARANTINE_FILE"
    assert payload["target_file"] == event["file"]["path"]


def test_quarantine_file_does_not_auto_fire_on_severity_alone() -> None:
    event = {"host_id": "host-1", "file": {"path": "/etc/rc.local"}}
    for level in (12, 13, 14, 16):
        action = ActiveResponseEngine.resolve_action(level=level, event=event, custom_action=None)
        assert action is None or action.action != "QUARANTINE_FILE"

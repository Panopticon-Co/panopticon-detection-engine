"""Coverage for ActiveResponseAction/ProcessTree carrying process.start_time_ticks
through to a TERMINATE_PROCESS recommendation, per
panopticon-response-engine/docs/adr/002-terminate-process-start-time-threading.md.
"""

from src.alerting.active_response import ActiveResponseEngine
from src.correlation.process_tree import ProcessTree


def test_resolve_action_carries_start_time_ticks_from_the_triggering_event() -> None:
    event = {
        "host_id": "host-1",
        "process": {"pid": 4242, "process_guid": "guid-1", "start_time_ticks": 123456789},
    }
    action = ActiveResponseEngine.resolve_action(level=12, event=event, custom_action="TERMINATE_PROCESS")
    assert action is not None
    assert action.target_pid == 4242
    assert action.target_start_time_ticks == 123456789
    payload = action.to_dict()
    assert payload["target_start_time_ticks"] == 123456789


def test_resolve_action_omits_start_time_ticks_when_the_event_does_not_carry_it() -> None:
    event = {"host_id": "host-1", "process": {"pid": 4242, "process_guid": "guid-1"}}
    action = ActiveResponseEngine.resolve_action(level=12, event=event, custom_action="TERMINATE_PROCESS")
    assert action is not None
    assert action.target_start_time_ticks is None
    # to_dict() drops None fields -- a missing key, not a null, must reach
    # response_engine.translate_recommendation so it fails closed there too.
    assert "target_start_time_ticks" not in action.to_dict()


def test_process_tree_retains_start_time_ticks_on_process_create() -> None:
    tree = ProcessTree()
    node = tree.add_process(
        {
            "event_type": "process_create",
            "host_id": "host-1",
            "timestamp": "2026-09-13T00:00:00.000Z",
            "process": {"process_guid": "guid-1", "pid": 4242, "name": "evil.exe", "start_time_ticks": 987654321},
        }
    )
    assert node.start_time_ticks == 987654321
    assert tree.get_node("guid-1").start_time_ticks == 987654321


def test_process_tree_leaves_start_time_ticks_none_when_absent() -> None:
    tree = ProcessTree()
    node = tree.add_process(
        {
            "event_type": "process_create",
            "host_id": "host-1",
            "timestamp": "2026-09-13T00:00:00.000Z",
            "process": {"process_guid": "guid-2", "pid": 99, "name": "cmd.exe"},
        }
    )
    assert node.start_time_ticks is None

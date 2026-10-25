| Scenario | Kind | Wire 0.2-0.4 | Events | Alerts | Unexpected rules | Incidents (expected) | Root | Stage to incident (s) | Responses |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| benign_workstation | benign | yes | 88 | 0 | - | 0 (0) | - | - | - |
| download_execute_lsass_dump | attack chain | yes | 14 | 3 | CORR-RISK-001 | 1 (1) | invoice_2026.exe | 5.0 | record-only (no start_time_ticks) 1, auto 1 |
| fileless_powershell_lsass_dump | attack chain | no (0.5) | 11 | 11 | CORR-RISK-001, DET-PROC-001, DET-PROC-009, DET-PROC-011, DET-PROC-012, DET-SEQ-001 | 1 (1) | winword.exe | 3.0 | record-only (no start_time_ticks) 6, auto 3 |
| internal_reconnaissance | single tactic | yes | 21 | 4 | CORR-RISK-001, DET-PROC-008 | 0 (0) | - | - | record-only (no start_time_ticks) 1, auto 1 |
| office_macro_to_c2_and_persistence | attack chain | yes | 57 | 12 | CORR-RISK-001, DET-NET-001, DET-PROC-009, DET-PROC-012 | 1 (1) | winword.exe | 1.0 | record-only (no start_time_ticks) 8, auto 1 |
| ransomware_precursors_and_encryption | attack chain | yes | 20 | 5 | CORR-RISK-001 | 1 (1) | upd.exe | 1.0 | record-only (no start_time_ticks) 4, auto 1 |
| sibling_noise_no_merge | single tactic | yes | 5 | 3 | CORR-RISK-001 | 0 (0) | - | - | record-only (no start_time_ticks) 1, auto 1 |

Summary: {"scenarios": 7, "attack_chains": 4, "attack_chains_detected": 4, "attack_chains_incident_correct": 4, "no_incident_scenarios": 2, "no_incident_scenarios_correct": 2, "no_incident_scenarios_detected": 2, "benign_scenarios": 1, "benign_events": 88, "benign_alerts": 0, "benign_incidents": 0, "replay_idempotent": true, "median_stage_to_incident_s": 2.0, "max_ms_per_event": 0.31}

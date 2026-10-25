| Scenario | Kind | Wire 0.2-0.4 | Events | Alerts | Unexpected rules | Incidents (expected) | Root | Stage to incident (s) | Responses |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| benign_workstation | benign | yes | 96 | 0 | - | 0 (0) | - | - | - |
| download_execute_lsass_dump | attack chain | yes | 19 | 3 | CORR-RISK-001 | 1 (1) | invoice_2026.exe | 5.0 | analyst-approval 2, auto 1 |
| fileless_powershell_lsass_dump | attack chain | no (0.5) | 16 | 11 | CORR-RISK-001, DET-PROC-001, DET-PROC-009, DET-PROC-011, DET-PROC-012, DET-SEQ-001 | 1 (1) | winword.exe | 3.0 | analyst-approval 8, auto 3 |
| internal_reconnaissance | single tactic | yes | 28 | 4 | CORR-RISK-001, DET-PROC-008 | 0 (0) | - | - | analyst-approval 1, auto 1 |
| office_macro_to_c2_and_persistence | attack chain | yes | 64 | 12 | CORR-RISK-001, DET-NET-001, DET-PROC-009, DET-PROC-012 | 1 (1) | winword.exe | 1.0 | analyst-approval 10, auto 1 |
| ransomware_precursors_and_encryption | attack chain | yes | 25 | 5 | CORR-RISK-001 | 1 (1) | upd.exe | 1.0 | analyst-approval 5, auto 1 |
| sibling_noise_no_merge | single tactic | yes | 10 | 3 | CORR-RISK-001 | 0 (0) | - | - | analyst-approval 1, auto 1 |

Summary: {"scenarios": 7, "attack_chains": 4, "attack_chains_detected": 4, "attack_chains_incident_correct": 4, "no_incident_scenarios": 2, "no_incident_scenarios_correct": 2, "no_incident_scenarios_detected": 2, "benign_scenarios": 1, "benign_events": 96, "benign_alerts": 0, "benign_incidents": 0, "replay_idempotent": true, "median_stage_to_incident_s": 2.0, "max_ms_per_event": 0.3}

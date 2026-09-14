## Summary
What does this PR change and why?

## Changes
- Summary of the detection rule, correlation engine, ingestion, or remediation-recommendation
  changes.

## Type of Change
- [ ] New MITRE ATT&CK detection rule
- [ ] Correlation / process tree improvement
- [ ] Ingestion adapter update (Officer / Sysmon / Schema version)
- [ ] False positive / false negative fix
- [ ] Documentation only
- [ ] Other

## Testing
- [ ] Tests added / updated under `tests/`
- [ ] `pytest -v tests/` passes locally
- [ ] New/changed rules include test coverage

## Security Impact
- [ ] No security impact
- [ ] Changes detection logic (describe expected effect on true/false positive rate)
- [ ] Touches the Panopticon event schema or `ActiveResponseAction` vocabulary (explain
      cross-repository impact below)
- [ ] Adds no live execution path (this repo remains recommendation-only — see
      README.md#detection-vs-execution-boundary)

## Documentation
- [ ] README / docs updated if behavior, flags, or rule count changed
- [ ] `docs/OFFICER_INTEGRATION.md` updated if the ingestion contract changed

## Cross-Repository Impact
- [ ] None
- [ ] Affects `panopticon-response-engine` (ActiveResponseAction vocabulary)
- [ ] Affects `panopticon-manager` or the Panopticon event schema
- [ ] Affects `panopticon-agent` / `panopticon-linux-agent` telemetry contract

## Checklist
- [ ] Adheres to the current Panopticon event schema
- [ ] No real process-termination/quarantine/lockout execution added

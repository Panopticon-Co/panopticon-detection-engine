# Security Policy

`eyedetect` (panopticon-detection-engine) is a capstone/research security project. There is no
SLA, but reports are handled on a best-effort basis.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability, rule-evasion technique,
or a flaw that could be misused if disclosed publicly.

Instead, report privately via GitHub Security Advisories:

<https://github.com/Panopticon-Co/panopticon-detection-engine/security/advisories/new>

Include, where possible:

- A description of the issue and its potential impact.
- Reproduction steps and, if relevant, a sample telemetry/attack payload.
- Affected rule ID(s), module(s), or file path(s).

## Supported versions

This project does not yet maintain multiple released versions; security fixes are applied to the
`main` branch.

## Scope note

This engine produces detections and response **recommendations** only — it does not execute
process termination, file quarantine, account lockout, or any other live endpoint action (see the
detection-vs-execution boundary in [`README.md`](README.md)). Reports about "remediation" should
be scoped to the recommendation logic, not assumed live-execution behavior.

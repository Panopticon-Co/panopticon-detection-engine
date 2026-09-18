# Panopticon Versioning Policy

This document defines how versions are assigned across the Panopticon polyrepo
(`panopticon-agent`, `panopticon-linux-agent`, `panopticon-detection-engine`,
`panopticon-manager`, `panopticon-response-engine`, `panopticon-contracts`,
`panopticon-console`). It
exists to remove ambiguity between a *coordinated platform release* and the
various *component / build identifiers* that appear in individual files.

## 1. Coordinated Panopticon release version (authoritative)

The version of "Panopticon" is a single [SemVer](https://semver.org/) string,
applied as an **annotated Git tag with the same name on every repository
participating in that release**.

- `v1.0.0` — the process-creation vertical slice (Officer -> Schema 0.2 ->
  detection-engine -> `DET-PROC-011` -> `alerts.ndjson` -> console -> browser),
  tagged on all three repos.
- `v1.1.0` — the coordinated release for the current **V2 + V3 additive work**:
  the opt-in `--reliable` reliability pipeline (V2) and the additive Schema 0.3
  five-family telemetry ingestion (V3). Every change since `v1.0.0` is additive
  and backward-compatible, so this is a **MINOR** bump, not `v1.2.0` and not
  `v2.0.0`.

Rules:

- A coordinated release tags **all three** repositories with the **same**
  version, even if a given repo's change set for that release is small (e.g. the
  agent received only V3 telemetry work for `v1.1.0`; the engine and console
  received V2 + V3).
- The tags are **independent Git refs** (one per repo, each on that repo's own
  `main`) but are **intentionally coordinated** — same name, same release
  window, shared release notes.
- Additive / backward-compatible increments are **MINOR**. A breaking change to
  a published contract (the event schema, the `/api/alerts` shape, the default
  CLI behavior) would be **MAJOR**.

## 2. Schema version

`schema/event.schema.json` in `panopticon-agent` carries its own
`schema_version` (currently `0.3`, additive over `0.2`). It is versioned
**independently** of the coordinated release tag because producers and consumers
negotiate it: the detection-engine ingestion adapter accepts `0.1`, `0.2`, and
`0.3`. A schema change does not force a coordinated release bump, and vice
versa.

## 3. Component / build identifiers (may lag the release tag)

The following strings are **not** the coordinated release version. They are
component- or build-scoped identifiers and are allowed to differ from the
release tag, provided that difference is documented here.

| Identifier | Location | Meaning | Current value |
|---|---|---|---|
| CMake project version | `panopticon-agent/CMakeLists.txt` (`project(officer VERSION ...)`) | Build-manifest identifier for the `officer` CMake project. Drives no packaging or compatibility check today. | `0.2.0` (intentionally decoupled) |
| vcpkg manifest version | `panopticon-agent/vcpkg.json` (`version-string`) | vcpkg manifest version for the agent application (not a consumed library). Inert for an end-user app. | `0.2.0` (intentionally decoupled) |
| Agent runtime version | `panopticon-agent/include/panopticon/officer/telemetry/panopticon_event.hpp` (`kAgentVersion`) | The value emitted in each event's `agent.version` field. Tracks the telemetry/schema capability, not the release tag. | `0.3.0` |
| Console `Server:` header | `panopticon-console/app.py` (`server_version`) | HTTP `Server:` response-header display string. Cosmetic; no client or test depends on its value. | `PanopticonConsole/1.0` |

Policy: a component/build identifier is changed **only** when it is genuinely
meaningful for that component (e.g. a real packaging or ABI concern), never
merely to match the release tag. Any such decoupling must be listed in the
table above. As of `v1.1.0` the agent CMake/vcpkg `0.2.0` values and the
console `Server:` header are **left unchanged** and treated as decoupled
build/display identifiers.

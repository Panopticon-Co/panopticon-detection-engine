# Contributing to eyedetect

Thanks for your interest in contributing to `eyedetect` (panopticon-detection-engine).

## Development setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/panopticon-detection-engine.git
   cd panopticon-detection-engine
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Run the test suite** (this is the same command CI runs — see
   [`.github/workflows/ci.yml`](.github/workflows/ci.yml)):
   ```bash
   pytest -v tests/
   ```

There is no linter/formatter configuration (e.g. `ruff`, `black`) checked into this repository at
present — follow the existing code style in the module you're touching. If you add one, wire it
into CI in the same change and mention it here.

## Pull request guidelines

- Add or update tests under `tests/` for any behavior change, including new or modified detection
  rules.
- New detection rules should include a MITRE ATT&CK `tactic`/`technique` mapping and, where
  applicable, an `active_response` recommendation.
- Never wire a rule or code path to real process termination, file quarantine, account lockout, or
  any other live endpoint action — this repository is recommendation-only by design (see
  [README.md](README.md#detection-vs-execution-boundary)). Do not add a `subprocess`, `os.kill`,
  `winreg`, or socket call intended to actually execute a response.
- Do not change the Panopticon event schema, or the `ActiveResponseAction` vocabulary, without
  explaining the cross-repository impact (consumers include
  [`panopticon-response-engine`](https://github.com/Panopticon-Co/panopticon-response-engine) and
  [`panopticon-manager`](https://github.com/Panopticon-Co/panopticon-manager)) and updating every
  affected consumer/test in the same change.
- Use descriptive commit messages; [Conventional Commits](https://www.conventionalcommits.org/)
  style (`fix:`, `feat:`, `docs:`, `test:`, ...) is preferred.
- Fill out the PR template, including the Security Impact and Cross-Repository Impact sections.

## Reporting security issues

Do not use pull requests or public issues for security vulnerabilities — see
[`SECURITY.md`](SECURITY.md).

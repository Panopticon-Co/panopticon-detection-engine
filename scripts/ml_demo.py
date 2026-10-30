"""The ML demo segment: real model, real inference path, real failure behaviour.

    python scripts/ml_demo.py [--model data/models/v7_v5] [--markdown out.md]

Everything printed is computed by this run; nothing is typed in by hand.

1. **Load.** The bundle loads through ``factory.build_ml_stage``, the loader the
   manager uses. The script prints the model version, artifact sha and
   thresholds.
2. **Corpus fixtures.** Every corpus scenario replays through the fully wired
   engine with the model in ``active`` mode. The script prints each scored
   process start's raw score and band, and which ``ML-PROC-*`` findings were
   raised. The positive fixture is the fileless PowerShell chain; the benign
   fixture is the workstation scenario.
3. **Demo commands.** Synthetic ``process_create`` events are shaped like the
   harmless commands the Windows demo runs (docs/capstone/WINDOWS_HANDOFF.md).
   These are a *prediction* for the live run, not a measurement of it: live
   events carry the agent's own paths and parents.
4. **Failure drill.** The same scenario replays with a corrupted copy of the
   bundle. ML disables itself, and the rule alerts must equal a rules-only run.

These are synthetic engineering fixtures and say nothing about detection
quality. The measured held-out numbers are in docs/ml/MODEL_CARD.md.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from panopticon_detection.factory import build_detection_run, build_ml_stage  # noqa: E402
from panopticon_detection.ingestion.officer_adapter import OfficerIngestionAdapter  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"
POSITIVE, BENIGN = "fileless_powershell_lsass_dump", "benign_workstation"
DRILL = "download_execute_lsass_dump"
SYSTEM32 = "C:\\Windows\\System32\\"
PS = SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe"
# (label, image, command line, parent image): the Windows demo's harmless triggers.
DEMO_COMMANDS = [
    ("benign: notepad", SYSTEM32 + "notepad.exe", "notepad.exe", "C:\\Windows\\explorer.exe"),
    ("benign: whoami", SYSTEM32 + "whoami.exe", "whoami", PS),
    ("1 recon", SYSTEM32 + "whoami.exe", "whoami /priv", PS),
    ("2 scheduled task", SYSTEM32 + "schtasks.exe",
     "schtasks /create /tn PanopticonDemo /tr notepad.exe /sc once /st 23:59 /f", PS),
    ("3 credential list", SYSTEM32 + "cmdkey.exe", "cmdkey /list", PS),
    ("4 certutil download", SYSTEM32 + "certutil.exe",
     "certutil -urlcache -split -f http://127.0.0.1:8080/demo.txt C:\\Users\\demo\\AppData\\Local\\Temp\\ct.txt", PS),
    ("5 run key", SYSTEM32 + "reg.exe",
     "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v PanopticonDemo /t REG_SZ /d notepad.exe /f", PS),
    ("6 discovery", SYSTEM32 + "systeminfo.exe", "systeminfo", PS),
    ("7 encoded powershell", PS,
     "powershell -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFAAYQBuAG8AcAB0AGkAYwBvAG4AIABkAGUAbQBvACcA",
     PS),
]


def _events(name):
    for line in (CORPUS / name / "events.ndjson").read_text(encoding="utf-8").splitlines():
        event = OfficerIngestionAdapter.parse_line(line)
        if event:
            yield event


def _replay(name, model=None, mode="active"):
    run, context = build_detection_run(ROOT / "rules", ml_model_path=model, ml_mode=mode)
    alerts, scores = [], []
    for event in _events(name):
        if model and run.ml_stage is not None:
            result = run.ml_stage.score(event)
            if result is not None:
                scores.append(((event.get("process") or {}).get("name"), result.raw_score, result.band))
            # score() is pure: process_event scores the event again on the real path.
        alerts += run.process_event(event)
    return alerts, scores, context.stats()


def _demo_event(i, image, command_line, parent):
    return {
        "event_type": "process_create", "host_id": "DEMO-WIN", "event_id": f"demo-{i}",
        "timestamp": f"2026-10-30T10:00:{i:02d}Z",
        "process": {"pid": 4000 + i, "name": image.rsplit("\\", 1)[-1], "executable": image,
                    "command_line": command_line},
        "parent": {"pid": 3000, "name": parent.rsplit("\\", 1)[-1], "executable": parent},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--model", default=str(ROOT / "data" / "models" / "v7_v5"))
    parser.add_argument("--markdown", type=Path, help="also write the report here")
    args = parser.parse_args()
    logging.basicConfig(level=logging.CRITICAL)  # the drill's "DISABLED" line is reported below instead
    out = []
    say = out.append

    stage, status = build_ml_stage(args.model, "active")
    if stage is None:
        print(f"model did not load: {status}", file=sys.stderr)
        return 1
    b = stage.bundle
    say("# ML demo: expected output (generated by `scripts/ml_demo.py`)\n")
    say("Synthetic engineering fixtures, not a detection-quality claim; held-out numbers: "
        "`docs/ml/MODEL_CARD.md`.\n")
    say("## 1. The model loads\n")
    say(f"- model_version `{b.model_version}`, featurizer {b.featurizer_version}")
    say(f"- artifact_sha256 `{b.artifact_sha256}`")
    say(f"- thresholds (raw margin): alert {b.alert_raw:.4f}, high {b.high_raw:.4f}\n")

    say("## 2. Corpus fixtures through the engine (active mode)\n")
    say("| Scenario | Starts scored | Max score (process) | ML findings | Rule alerts |")
    say("|---|---|---|---|---|")
    for scenario in sorted(p.name for p in CORPUS.iterdir() if (p / "events.ndjson").is_file()):
        alerts, scores, _ = _replay(scenario, args.model)
        top = max(scores, key=lambda s: s[1]) if scores else None
        ml = sorted(f"{a.rule_id} ({a.evidence.get('process.name')} {a.ml['raw_score']:.2f})"
                    for a in alerts if a.detection_source == "ml")
        rules = sum(a.detection_source != "ml" for a in alerts)
        marker = " **positive**" if scenario == POSITIVE else " **benign**" if scenario == BENIGN else ""
        say(f"| {scenario}{marker} | {len(scores)} | "
            f"{f'{top[1]:.2f} ({top[0]})' if top else '-'} | {', '.join(ml) or 'none'} | {rules} |")

    say("\n## 3. The Windows demo commands as synthetic events (a prediction, not a measurement)\n")
    say("| Command | Raw score | Band |")
    say("|---|---|---|")
    for i, (label, image, command_line, parent) in enumerate(DEMO_COMMANDS):
        result = stage.score(_demo_event(i, image, command_line, parent))
        say(f"| {label}: `{command_line[:60]}` | {result.raw_score:.2f} | {result.band or 'below threshold'} |")

    say("\n## 4. Failure drill: a corrupted bundle\n")
    with tempfile.TemporaryDirectory() as tmp:
        broken = Path(tmp) / "broken"
        shutil.copytree(args.model, broken)
        model_json = broken / "model.json"
        data = bytearray(model_json.read_bytes())
        data[len(data) // 2] ^= 0x01
        model_json.write_bytes(bytes(data))
        with_broken, _, stats = _replay(DRILL, str(broken))
        plain, _, _ = _replay(DRILL)
    same = [a.to_dict() for a in with_broken] == [a.to_dict() for a in plain]
    say(f"- `ml_state`: **{stats.get('ml_state')}** ({stats.get('ml_error', '')[:90]}...)")
    say(f"- rule alerts on `{DRILL}`: {len(with_broken)} with the broken model, {len(plain)} rules-only; "
        f"identical: **{same}**")
    report = "\n".join(out) + "\n"
    print(report)
    if args.markdown:
        args.markdown.write_text(report, encoding="utf-8")
    return 0 if same and stats.get("ml_state") == "disabled" else 1


if __name__ == "__main__":
    raise SystemExit(main())

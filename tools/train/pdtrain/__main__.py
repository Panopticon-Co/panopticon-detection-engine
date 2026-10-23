"""``python -m pdtrain <step>`` -- run one pipeline step (run from tools/train)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

REPO = Path(__file__).resolve().parents[3]
DATA = REPO / "data"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="pdtrain")
    sub = parser.add_subparsers(dest="step", required=True)

    fetch = sub.add_parser("fetch", help="download and pin the training sources")
    fetch.add_argument(
        "--groups", nargs="+", default=["static", "otrf", "attack_data", "compound", "optc"],
        choices=["static", "otrf", "attack_data", "compound", "optc"],
    )

    norm = sub.add_parser("normalize", help="raw sources -> per-source row tables")
    norm.add_argument(
        "--sources", nargs="+", default=["attack_data", "otrf", "otrf_compound", "botsv1", "officer_vm"],
        choices=["attack_data", "otrf", "otrf_compound", "botsv1", "officer_vm", "optc"],
    )

    lab = sub.add_parser("label", help="row tables -> labelled, de-duplicated rows")
    lab.add_argument(
        "--sources", nargs="+", default=["attack_data", "otrf", "otrf_compound", "botsv1", "officer_vm", "optc"],
        choices=["attack_data", "otrf", "otrf_compound", "botsv1", "officer_vm", "optc"],
    )

    exp = sub.add_parser("experiment", help="train, evaluate, export the bundle")
    exp.add_argument("--version", default="v1")
    exp.add_argument("--officer-train", action="store_true",
                     help="train on the first half (by time) of the agent-recorded benign data")
    exp.add_argument("--optc-train", action="store_true",
                     help="train on the OpTC host range that is not held out")

    sub.add_parser("comiset", help="stream COMISET's real environment; keep Sysmon process starts")
    sub.add_parser("atlasv2", help="stream ATLASv2; keep Sysmon process starts with REAPr labels (final test)")

    args = parser.parse_args(argv)
    if args.step == "comiset":
        import json
        import tempfile

        from pdtrain.comiset import stream

        spool = Path(tempfile.gettempdir()) / "pdtrain-comiset-spool"
        manifest = stream(DATA / "rows", spool, Path(__file__).resolve().parent.parent / "pins.json")
        print(json.dumps(manifest, indent=2), flush=True)
        return 0 if manifest["complete"] else 1
    if args.step == "atlasv2":
        import json
        import tempfile

        from pdtrain.atlasv2 import stream as stream_atlas

        spool = Path(tempfile.gettempdir()) / "pdtrain-atlasv2-spool"
        manifest = stream_atlas(DATA / "rows", spool, Path(__file__).resolve().parent.parent / "pins.json",
                                DATA / "raw" / "atlasv2")
        print(json.dumps(manifest, indent=2), flush=True)
        return 0 if manifest["complete"] else 1
    if args.step == "experiment":
        import json

        from pdtrain.experiment import run

        results = run(DATA, REPO, export_dir=DATA / "models" / args.version, officer_train=args.officer_train,
                      optc_train=args.optc_train)
        out = DATA / "experiment"
        out.mkdir(parents=True, exist_ok=True)
        (out / f"results_{args.version}.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        (out / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out / 'results.json'}")
        return 0
    if args.step == "label":
        import json

        from pdtrain.label import label_all

        print(json.dumps(label_all(DATA / "rows", DATA / "labelled", args.sources), indent=2))
        return 0
    if args.step == "fetch":
        from pdtrain.fetch import fetch_all

        return fetch_all(DATA / "raw", args.groups)
    if args.step == "normalize":
        import json

        from pdtrain.normalize import normalize_all

        print(json.dumps(normalize_all(DATA / "raw", DATA / "rows", args.sources), indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())

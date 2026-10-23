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
        choices=["attack_data", "otrf", "otrf_compound", "botsv1", "officer_vm", "optc", "officer_sealed"],
    )

    lab = sub.add_parser("label", help="row tables -> labelled, de-duplicated rows")
    lab.add_argument(
        "--sources", nargs="+",
        default=["attack_data", "otrf", "otrf_compound", "botsv1", "officer_vm", "optc", "atlasv2"],
        choices=["attack_data", "otrf", "otrf_compound", "botsv1", "officer_vm", "optc", "atlasv2"],
    )

    exp = sub.add_parser("experiment", help="train, evaluate, export the bundle")
    exp.add_argument("--version", default="v1")
    exp.add_argument("--officer-train", action="store_true",
                     help="train on the first half (by time) of the agent-recorded benign data")
    exp.add_argument("--optc-train", action="store_true",
                     help="train on the OpTC host range that is not held out")

    lo = sub.add_parser("loeo", help="leave-one-environment-out evaluation of named recipes (pdtrain.loeo)")
    lo.add_argument("--recipes", nargs="+", default=["v6_recipe"])
    lo.add_argument("--out", default="baseline")
    v7 = sub.add_parser("v7", help="v7: LOEO candidates, selection, criteria S1-S6, export the bundle")
    v7.add_argument("--version", default="v7")
    v7.add_argument("--final-only", action="store_true", help="only train and export --recipe (rebuild check)")
    v7.add_argument("--recipe", help="recipe for --final-only")

    sub.add_parser("comiset", help="stream COMISET's real environment; keep Sysmon process starts")
    atl = sub.add_parser("atlasv2", help="stream ATLASv2; keep Sysmon process starts with REAPr labels")
    atl.add_argument("--all-families", action="store_true",
                     help="keep every Sysmon event as canonical events in data/canonical/atlasv2 (context model)")
    fin = sub.add_parser("final-test", help="score the sealed agent recording once with a frozen bundle")
    fin.add_argument("--version", required=True)
    fin.add_argument("--source", default="officer_sealed")
    fin.add_argument("--freeze", action="store_true", help="mark the bundle as the final candidate first")

    args = parser.parse_args(argv)
    if args.step in ("loeo", "v7"):
        import json

        from pdtrain import loeo

        out_dir = DATA / "experiment"
        out_dir.mkdir(parents=True, exist_ok=True)
        if args.step == "loeo":
            unknown = sorted(set(args.recipes) - set(loeo.RECIPES))
            if unknown:
                parser.error(f"unknown recipes {unknown}; known: {sorted(loeo.RECIPES)}")
            result = loeo.run_loeo(DATA, REPO, args.recipes)
            path = out_dir / f"loeo_{args.out}.json"
        elif args.final_only:
            if args.recipe not in loeo.RECIPES:
                parser.error(f"--final-only needs --recipe, one of {sorted(loeo.RECIPES)}")
            result = loeo.final_only(DATA, REPO, args.version, args.recipe)
            path = out_dir / f"final_only_{args.version}.json"
        else:
            result = loeo.run_v7(DATA, REPO, args.version)
            path = out_dir / f"results_{args.version}.json"
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path}")
        return 0
    if args.step == "comiset":
        import json
        import tempfile

        from pdtrain.comiset import stream

        spool = Path(tempfile.gettempdir()) / "pdtrain-comiset-spool"
        manifest = stream(DATA / "rows", spool, Path(__file__).resolve().parent.parent / "pins.json")
        print(json.dumps(manifest, indent=2), flush=True)
        return 0 if manifest["complete"] else 1
    if args.step == "final-test":
        import json

        from pdtrain.final_test import run as final_run

        result = final_run(DATA, REPO, args.version, source=args.source, freeze=args.freeze)
        out = DATA / "experiment" / f"final_test_{args.version}.json"
        out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out}")
        return 0
    if args.step == "atlasv2":
        import json
        import tempfile

        from pdtrain.atlasv2 import stream as stream_atlas
        from pdtrain.atlasv2 import stream_all_families

        spool = Path(tempfile.gettempdir()) / "pdtrain-atlasv2-spool"
        pins = Path(__file__).resolve().parent.parent / "pins.json"
        if args.all_families:
            manifest = stream_all_families(DATA / "canonical" / "atlasv2", spool, pins)
        else:
            manifest = stream_atlas(DATA / "rows", spool, pins, DATA / "raw" / "atlasv2")
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

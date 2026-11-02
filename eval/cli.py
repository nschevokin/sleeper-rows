"""``python -m eval.cli run|report|all --config eval/configs/<mode>.yaml``"""

from __future__ import annotations

import argparse
from pathlib import Path

from eval.report import build_report
from eval.runner import load_config, run_matrix


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="eval")
    ap.add_argument("command", choices=["run", "report", "all"])
    ap.add_argument("--config", required=True)
    ap.add_argument("--out-dir", default=None, help="override the config's out_dir")
    ap.add_argument("--max-trials", type=int, default=None)
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    if args.out_dir:
        cfg.out_dir = args.out_dir
    if args.max_trials is not None:
        cfg.max_trials = args.max_trials
    out = Path(cfg.out_dir) / cfg.name
    if args.command in ("run", "all"):
        out = run_matrix(cfg, config_path=args.config)
    if args.command in ("report", "all"):
        print(f"wrote {build_report(out, cfg)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

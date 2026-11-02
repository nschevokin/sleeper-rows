"""``python -m pipeline.cli <command>``: ingest, build, profile, freeze, pin-models, download.

Every command is idempotent: ingest only lands new or changed rows, build only enriches rows it has
not enriched yet, freeze and pin-models rewrite their output file deterministically.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import polars as pl
import yaml
from taintguard.contracts import load_contracts

from agents.enrichment import DiskCache, Enricher
from agents.llm import ModelClient, OllamaModel
from agents.stub import StubModel
from pipeline import build
from pipeline.ingest import SchemaDrift, load_refs, read_flat
from pipeline.snapshot import load_snapshot, sha256_file
from pipeline.warehouse import MemoryWarehouse, Warehouse

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"


def _model(mode: str, name: str | None, lock: Path) -> ModelClient:
    if mode == "stub":
        return StubModel()
    if not name:
        raise SystemExit("--model is required for --mode ollama")
    digest = None
    if lock.exists():
        digest = (
            (yaml.safe_load(lock.read_text(encoding="utf-8")) or {}).get("models", {}).get(name)
        )
    return OllamaModel(name, digest=digest)


def cmd_ingest(a: argparse.Namespace) -> int:
    snap, contracts = load_snapshot(a.snapshot), load_contracts(CONTRACTS)
    wh = Warehouse(a.warehouse)
    res = build.ingest_snapshot(wh, snap, contracts, with_updates=not a.no_updates)
    print(json.dumps([r.summary() for r in res], indent=1, default=str))
    return 0


def cmd_build(a: argparse.Namespace) -> int:
    snap, contracts = load_snapshot(a.snapshot), load_contracts(CONTRACTS)
    wh = Warehouse(a.warehouse)
    model = _model(a.mode, a.model, ROOT / "models.lock.yaml")
    refs = load_refs(snap.reference["components"], snap.reference["vehicles"])
    systems = sorted({c.split(":", 1)[0].upper() for c in refs["components"]})
    cache = (
        None
        if snap.synthetic
        else DiskCache(Path(a.snapshot).resolve().parent / ".cache" / "enrich.jsonl")
    )
    enricher = Enricher(
        model, systems, cache=cache, contract=contracts.model("enriched_complaints")
    )
    res = build.build_all(
        wh,
        snap,
        contracts,
        enricher,
        with_updates=not a.no_updates,
        progress=lambda m: print(f"[{m}]", flush=True),
    )
    res["model"] = {"name": model.name, "digest": model.digest, "synthetic": snap.synthetic}
    print(json.dumps(res, indent=1, default=str))
    return 0


def cmd_profile(a: argparse.Namespace) -> int:
    """Check the real files against the contracts before trusting them (recalls layout is provisional)."""
    snap, contracts = load_snapshot(a.snapshot), load_contracts(CONTRACTS)
    report: dict[str, Any] = {"snapshot": snap.name, "files": {}}
    roles = {
        "complaints": "raw_complaints",
        "investigations": "raw_investigations",
        "recalls": "raw_recalls",
    }
    for role, model in roles.items():
        path = Path(snap.files[role])
        hist: dict[int, int] = {}
        first = ""
        with path.open("rb") as fh:
            for i, raw in enumerate(fh):
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                hist[line.count("\t") + 1] = hist.get(line.count("\t") + 1, 0) + 1
                if i == 0:
                    first = line
        spec = contracts.model(model)
        report["files"][role] = {
            "path": str(path), "bytes": path.stat().st_size, "sha256": sha256_file(path),
            "fields_per_line": dict(sorted(hist.items())), "contract_columns": len(spec.columns),
            "contract_allows": [spec.source.get("min_columns"), spec.source.get("max_columns")] if spec.source else None,
            "provisional": bool(spec.source and spec.source.get("provisional")),
            "first_line_preview": first[:200],
        }  # fmt: skip
        try:
            df = read_flat(path, spec)
            report["files"][role]["loaded_rows"] = df.height
            if role == "recalls":
                report["files"][role]["column_samples"] = {
                    c.name: df[c.name].head(2).to_list() for c in spec.columns[:12]
                }
        except SchemaDrift as exc:
            report["files"][role]["schema_drift"] = str(exc)
    mem = MemoryWarehouse()
    try:
        ing = build.ingest_snapshot(mem, snap, contracts, with_updates=not a.no_updates)
        report["ingest_dry_run"] = [r.summary() for r in ing]
    except SchemaDrift as exc:
        report["ingest_dry_run"] = f"schema drift: {exc}"
    text = json.dumps(report, indent=1, default=str)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


def cmd_quarantine(a: argparse.Namespace) -> int:
    """Why rows were quarantined: counts per failed check, example rows and the commonest values."""
    wh = Warehouse(a.warehouse)
    if not wh.exists("quarantine_complaints"):
        print("no quarantine_complaints table in this warehouse")
        return 1
    q = pl.from_arrow(wh.read("quarantine_complaints"))
    assert isinstance(q, pl.DataFrame)
    by = q.group_by("failed_tests").agg(pl.len().alias("rows")).sort("rows", descending=True)
    report: dict[str, Any] = {"total": q.height, "by_failed_tests": [], "top_compdesc": {}}
    for r in by.head(a.top).iter_rows(named=True):
        ex = q.filter(pl.col("failed_tests") == r["failed_tests"])["row_json"][0]
        report["by_failed_tests"].append(
            {"failed_tests": r["failed_tests"], "rows": r["rows"], "example": str(ex)[:300]}
        )
    comp: dict[str, int] = {}
    for js in q["row_json"].to_list():
        try:
            v = str(json.loads(js).get("COMPDESC", ""))
        except (ValueError, AttributeError):
            continue
        comp[v] = comp.get(v, 0) + 1
    report["top_compdesc"] = dict(sorted(comp.items(), key=lambda kv: -kv[1])[: a.top])
    print(json.dumps(report, indent=1, default=str))
    return 0


def cmd_freeze(a: argparse.Namespace) -> int:
    """Write snapshot.yaml for a data directory, pinning checksums and deriving the vocabularies.

    The vocabularies (components.txt, vehicles.csv) are the operator-approval point: review them
    before relying on results. A vehicle is approved when it appears at least --min-vehicle-count times.
    """
    d = Path(a.data_dir).resolve()
    contracts = load_contracts(CONTRACTS)
    spec = contracts.model("raw_complaints")
    cmpl = read_flat(d / "FLAT_CMPL.txt", spec)
    ref = d / "reference"
    ref.mkdir(exist_ok=True)
    comps = sorted(set(cmpl["COMPDESC"].str.to_uppercase().to_list()) - {""})
    (ref / "components.txt").write_text("\n".join(comps) + "\n", encoding="utf-8")
    veh = (
        cmpl.select(pl.col("MAKETXT").str.to_uppercase().alias("make"), pl.col("MODELTXT").str.to_uppercase().alias("model"))
        .filter((pl.col("make") != "") & (pl.col("model") != ""))
        .group_by(["make", "model"]).len().filter(pl.col("len") >= a.min_vehicle_count)
        .sort(["make", "model"]).drop("len")
    )  # fmt: skip
    veh.write_csv(ref / "vehicles.csv")
    updates = (
        sorted(str(p.relative_to(d)) for p in (d / "updates").glob("*.txt"))
        if (d / "updates").exists()
        else []
    )
    files = {
        "complaints": "FLAT_CMPL.txt",
        "investigations": "FLAT_INV.txt",
        "recalls": "FLAT_RCL.txt",
    }
    doc: dict[str, Any] = {
        "name": a.name, "source": "nhtsa", "synthetic": False, "snapshot_date": a.snapshot_date,
        "seed": a.seed, "date_range": {"start": a.start, "end": a.end},
        "label_window_days": a.label_window_days, "files": files, "updates": updates,
        "reference": {"components": "reference/components.txt", "vehicles": "reference/vehicles.csv"},
        "checksums": {k: sha256_file(d / v) for k, v in files.items()},
    }  # fmt: skip
    if a.makes:
        doc["scope"] = {"makes": a.makes, "max_enrich_rows": a.max_enrich_rows}
    out = Path(a.out)
    out.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    print(f"wrote {out} ({len(comps)} components, {veh.height} approved vehicles)")
    return 0


def cmd_pin_models(a: argparse.Namespace) -> int:
    r = httpx.get(f"{a.host.rstrip('/')}/api/tags", timeout=30)
    r.raise_for_status()
    have = {m["name"]: m["digest"] for m in r.json().get("models", [])}
    missing = [m for m in a.models if m not in have]
    if missing:
        print(f"not pulled: {missing}. Run `ollama pull <name>` first.", file=sys.stderr)
        return 1
    pinned = {m: have[m] for m in a.models}
    Path(a.out).write_text(
        yaml.safe_dump({"pinned_on": date.today().isoformat(), "models": pinned}), encoding="utf-8"
    )
    print(json.dumps(pinned, indent=1))
    return 0


def cmd_download(a: argparse.Namespace) -> int:
    src = yaml.safe_load(Path(a.sources).read_text(encoding="utf-8"))
    dest = Path(a.dest)
    dest.mkdir(parents=True, exist_ok=True)
    names = {
        "complaints": "FLAT_CMPL.txt",
        "investigations": "FLAT_INV.txt",
        "recalls": "FLAT_RCL.txt",
    }
    for role, url in src["files"].items():
        z = dest / Path(url).name
        print(f"GET {url}", flush=True)
        try:
            with httpx.stream("GET", url, timeout=600, follow_redirects=True) as r:
                r.raise_for_status()
                with z.open("wb") as fh:
                    for chunk in r.iter_bytes(1 << 20):
                        fh.write(chunk)
        except httpx.HTTPError as exc:
            print(f"download failed for {role}: {exc}. Check config/sources.yaml.", file=sys.stderr)
            return 1
        with zipfile.ZipFile(z) as zf:
            member = next(n for n in zf.namelist() if n.lower().endswith(".txt"))
            (dest / names[role]).write_bytes(zf.read(member))
    (dest / "updates").mkdir(exist_ok=True)
    for url in src.get("updates") or []:
        with httpx.stream("GET", url, timeout=600, follow_redirects=True) as r:
            r.raise_for_status()
            (dest / "updates" / Path(url).name).write_bytes(r.read())
    print(f"downloaded into {dest}; now run `pipeline.cli freeze --data-dir {dest} ...`")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("ingest", "build", "profile"):
        p = sub.add_parser(name)
        p.add_argument("--snapshot", required=True)
        p.add_argument("--no-updates", action="store_true")
        if name != "profile":
            p.add_argument("--warehouse", default=".warehouse")
        if name == "build":
            p.add_argument("--mode", choices=["stub", "ollama"], default="stub")
            p.add_argument("--model", default=None)
        if name == "profile":
            p.add_argument("--out", default=None)
    qp = sub.add_parser("quarantine")
    qp.add_argument("--warehouse", default=".warehouse")
    qp.add_argument("--top", type=int, default=10)
    f = sub.add_parser("freeze")
    f.add_argument("--data-dir", required=True)
    f.add_argument("--out", required=True)
    f.add_argument("--name", default="nhtsa-snapshot")
    f.add_argument("--snapshot-date", required=True)
    f.add_argument("--start", required=True, help="first LDATE in the backfill window, YYYY-MM-DD")
    f.add_argument("--end", required=True)
    f.add_argument("--seed", type=int, default=20261027)
    f.add_argument("--label-window-days", type=int, default=120)
    f.add_argument("--min-vehicle-count", type=int, default=20)
    f.add_argument("--makes", nargs="*", default=None)
    f.add_argument("--max-enrich-rows", type=int, default=None)
    m = sub.add_parser("pin-models")
    m.add_argument("--models", nargs="+", required=True)
    m.add_argument("--host", default="http://127.0.0.1:11434")
    m.add_argument("--out", default="models.lock.yaml")
    d = sub.add_parser("download")
    d.add_argument("--dest", required=True)
    d.add_argument("--sources", default=str(ROOT / "config" / "sources.yaml"))
    a = ap.parse_args(argv)
    return {
        "ingest": cmd_ingest, "build": cmd_build, "profile": cmd_profile, "freeze": cmd_freeze,
        "pin-models": cmd_pin_models, "quarantine": cmd_quarantine, "download": cmd_download,
    }[a.cmd](a)  # fmt: skip


if __name__ == "__main__":
    raise SystemExit(main())

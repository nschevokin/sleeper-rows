# Runbook: real data and real models (run on your laptop)

Nothing here has been executed against real NHTSA data or real Ollama models; the build environment could not reach either. Each step prints what it did; stop at the first surprise.

## 0. Prerequisites
`uv`, Python 3.13, [Ollama](https://ollama.com) running (`ollama serve`), 2-3 open models pulled (`ollama pull <name>`), about 10 GB free disk.

## 1. Setup and sanity check
```
make setup
make check                 # lint, types, tests (all on the synthetic fixture)
make eval MODE=stub        # stub matrix; REPORT.md carries the stub banner
```

## 2. Download and freeze a snapshot
```
uv run python -m pipeline.cli download --dest data/raw
```
The URLs in `config/sources.yaml` are **unverified**. If the download fails, open NHTSA's datasets page, fix the URLs, rerun. Then check the files against the contracts:
```
# snapshot.yaml must sit next to the data: its file paths are relative to it
uv run python -m pipeline.cli freeze --data-dir data/raw --out data/raw/snapshot.yaml \
  --snapshot-date <YYYY-MM-DD> --start <YYYY-MM-DD> --end <YYYY-MM-DD> \
  --makes <MAKE1> <MAKE2> --max-enrich-rows 20000
uv run python -m pipeline.cli profile --snapshot data/raw/snapshot.yaml
```
`profile` reports schema drift. The recalls contract layout (29 fields) is provisional: if `profile` reports drift, edit `contracts/recalls.yaml`. `--makes` and `--max-enrich-rows` keep enrichment affordable on a laptop; rerun `build` to continue from where it stopped.

## 3. Pin models
```
uv run python -m pipeline.cli pin-models --models <m1> <m2> --out models.lock.yaml
```
Copy the digests into `eval/configs/ollama.yaml`.

## 4. Build the warehouse
```
make run MODE=ollama MODEL=<name> SNAPSHOT=data/raw/snapshot.yaml
```

## 5. Evaluate
```
make eval MODE=ollama
```
Writes `results/ollama/REPORT.md`, Parquet tables and `trials.jsonl` (resumable: rerun to continue). Start with `--max-trials 50` through `python -m eval.cli run --config eval/configs/ollama.yaml --max-trials 50` to time it before the full matrix (models x 4 defenses x 6 families x 3 placements x 3 doses x 3 seeds).

## 6. Observatory
```
make observatory MODE=ollama
```
For stub-model runs add `--banner "Stub-model run: a worst-case bound, not a finding"` to `observatory.curate` or `observatory.compact`; the viewer then shows it above every replay. Traces shorter than 10 s are re-timed so they can be followed (real times stay in `t_real`).

Open `observatory/index.html` through any static server (`python -m http.server -d observatory`).

## 7. Scheduling
`SLEEPER_SNAPSHOT=... SLEEPER_MODE=ollama SLEEPER_MODEL=<name> uv run dagster dev -m pipeline.definitions`, then enable the `daily_build` schedule in the UI. It is **off by default**.

## 8. Publishing (your decision)
Nothing has been pushed. Create `nschevokin/sleeper-rows`, push, and enable GitHub Pages for the observatory yourself. Check `payloads_private/` and `data/` stay gitignored.

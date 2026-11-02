# Project state: sleeper-rows

Last updated: 2026-11-02. Branch `main`, local commits only (nothing pushed, no Pages, nothing published).

Status key: Implemented / Executed / Verified / Configured-for-unattended / Blocked

## Code
| Area | Status | Evidence |
|---|---|---|
| Taint guard library (`guard/`) and adapter | Implemented, Executed, Verified | library and adapter tests (A01-A12, GAP tests for documented misses) |
| Pipeline: ingest, staging, enrichment, gold, contracts, ledger, disk cache | Implemented, Executed on real NHTSA data (user's Mac), Verified on fixture | `make fixture run`; enrichment output is now validated against `contracts/enriched.yaml` |
| Dagster assets and daily schedule | Implemented, Executed, Verified; schedule STOPPED by default | `tests/test_dagster_defs.py` |
| Agents (enrichment, triage, analyst, data quality) and runtime | Implemented, Executed on llama3.1:8b | real baselines and 577 real-model trials, 0 errors |
| Attack suite (6 families, 3 placements, doses, sleeper triggers) and judge | Implemented, Executed, Verified | trial tests; success read from outputs and warehouse state, no LLM judge |
| Matrix runner, stats, report; exposure switches | Implemented, Executed, Verified | runs real1, real2, real3, worstcase |
| Enrichment-step attack (`eval/enrich_attack.py`, residual R2) | Implemented, Executed on the real model, Verified on the stub | `results_enrich/enrich_real/ENRICH_REPORT.md` |
| Observatory viewer and trace curator | Implemented, Executed (rendered real matrix output), Verified | render, compaction and curate tests |
| CI | Implemented (fixture, pipeline run, stub matrix, enrichment experiment); not run on GitHub | workflow file; same steps pass locally |
| Clean checkout | Executed, Verified | fresh clone: `make setup fixture check run eval`, 142 tests, 550 stub trials, 0 errors |
| Payload fuzzer | Not built, by decision | seeds are hand-written and fixed |
| Unattended operation | Not configured | |

## Real results (llama3.1:8b, pinned by digest, temperature 0, real NHTSA snapshot)
- Benign baselines: analyst 50-52.5%, data quality 44-69%, triage F1 0-0.38 (about 9 positives; noise), enrichment agreement 31.6% (majority baseline 16%).
- Downstream matrix, three conditions, 192 trials each: attack success 0-12% for every defense, all paired tests p = 1. Cause: exposure. Payloads rarely reach an agent (natural: 0%; extractive summaries: 12.5% of narrative trials; directed reading: 12.5%). The scripted worst-case agent was also fooled 0 of 96 trials per defense for the same reason.
- Defense costs on benign runs: prompt hardening halves analyst accuracy (0.45 vs 0.95; 0.07 vs 0.51 in real3); detector adds 7-20 s per run and is neutral on accuracy; TaintGuard keeps accuracy with a few benign flags (13 per clean baseline, 2 in real3) and query refusals.
- Enrichment-step attack (24 real complaints, matched controls): no defense 49% steered (severity override 91-100%, fake system note 74%, component flip 0%, planted summary 0%); prompt hardening 51% (no effect); detector 22% (-27 points, p < 0.001, drops 12.5% of ordinary narratives); TaintGuard 49% (identical by design, residual R2).

## Known limits
- One 8B model, one seed, blackbox seeds, single snapshot; intervals are wide. Triage is barely scorable.
- The guard library formats to about 1,400 lines against the ADR target of 700 or fewer. Nothing was cut.
- Recalls contract layout is still flagged provisional; run `pipeline.cli profile` on the real files before relying on it.
- Quarantine on real data (969 complaints) diagnosed: child car-seat equipment complaints with a different component vocabulary (see `docs/limitations.md`).

## Not code
- Write-up draft in `paper/` (4 pages; references unverified; numbers hand-copied from reports). Interview prep refreshed. Optional: the plan's 12-item checklist walk-through.
- Observatory scenarios from real traces: run `python -m observatory.curate --run results_real3/real3 --out observatory/replays`.

## Needs the user
1. Fix the commit author (`scripts/fix_author.sh`), then decisions on a personal GitHub repo (check `git config user.email` and `git remote -v` first, the Mac also has work GitHub), push, and enabling Pages. Nothing has been pushed or published.

# Limitations

1. **One model, small samples.** Real results come from llama3.1:8b (temperature 0, one seed). Most downstream cells hold 24-45 trials with 0-3 successes, so they bound the effect and do not rank defenses. Stub-model runs are plumbing checks and never findings.
2. **No adaptive attacker.** The suite is six fixed families with hand-written seeds. There is no automated payload search, so robustness against an attacker who tunes payloads against the guard is not claimed. Report guard results as "against these families".
3. **Residuals R1-R8** (`guard/README.md`) are by design outside the guard: volume poisoning, in-range typed values, tampering to another real cell, paraphrase without a contact token, unverifiable python declarations, disruption.
4. **Utility cost** (R6): refused queries and withheld cells are measured on benign runs and reported next to security results.
5. **Small open models** (2-3) on a laptop: results may not transfer to frontier models.
6. **Scope caps** (`--makes`, `--max-enrich-rows`) trade coverage for runtime; reports state the scope.
7. **Guard library size:** about 1,400 formatted lines against the ADR target of 700 or fewer.
8. **Recalls contract** layout is provisional until `pipeline.cli profile` has been run on the real recalls file.
9. **Observatory** replays of real runs show only what the traces contain; stub-model scenarios are labelled as a worst-case bound.
10. **Sleeper payloads** reach the analyst only when the poisoned row falls in the rows the agent reads; that dilution is part of the measured result.

## Enrichment-step experiment
- One model, a few dozen sampled complaints per cell, blackbox seeds by default, narrative placement
  only (field and batch placements do not change what the labeler reads).
- TaintGuard is not expected to stop the labeler being steered; measuring that gap is the point.

## What the real quarantine contains
On the real snapshot, 969 complaints are quarantined, all for one reason: `COMPDESC` is outside the
vehicle component vocabulary. They are child car seat complaints (Evenflo; values such as "Chest
Clip, Buckle, Harness", "Carry Handle, Shell, Base", model year 9999). NHTSA files equipment
complaints in the same flat file with a different vocabulary. The contract rejects them on purpose,
so equipment complaints are out of scope, and the data-quality agent's `unseen_component` category
is a real case, not only a synthetic one.

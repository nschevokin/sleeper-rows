# Interview prep

**One-minute pitch.** Agents that read warehouse text can be steered by whoever wrote that text. I built a small platform over NHTSA complaints, four LLM components, a fixed attack suite, and a taint-tracking guard that uses data contracts and SQL lineage to keep untrusted text away from tool-calling models. I measured it against simpler defenses, with its costs.

**Questions to be ready for**
- *Why lineage, not a detector?* Detectors judge text; lineage decides by provenance, so it holds for paraphrase and sleepers. Still leaves R1-R8.
- *What does the guard not stop?* Volume poisoning, in-range typed values, tampering to another real cell (`guard/README.md`).
- *Why not `sqlglot.lineage`?* It loses dependencies through table functions, EXISTS and literals; ADR 0004 section 1 lists the experiments.
- *Is it fair to the baselines?* Lineage tiers and runtime fixes apply to all defenses; only error redaction and canonical SQL are guard-only.
- *How do you know the numbers mean something?* Matched control per trial, dev/test split, bootstrap CIs, paired exact tests. Say plainly that downstream cells are small (24-45 trials, 0-3 successes) and bound the effect.
- *What about adaptive attackers?* Not claimed; the suite is fixed (limitations).
- *What would you do next?* More models and seeds, a severity cross-check against structured fields (deaths, injuries, fire) to close residual R2, an adaptive-attack study under a proper disclosure process.

**What I found (real runs, llama3.1:8b)**
- Attacks rarely reach the downstream agents: the LLM summariser removes the payload (0% survive enrichment); with extractive summaries 12.5% reach an agent. Attack success stays 0-3 of 24-45 trials per defense.
- The enrichment labeler is the weak point: override instructions change severity 91-100% of the time, a fake system note 74%.
- Costs: prompt hardening halves benign analyst accuracy (0.45 vs 0.95) and does not help; the detector cuts steering by 27 points (p < 0.001) but drops 12.5% of ordinary narratives and adds 7-20 s; TaintGuard keeps accuracy but does not defend the labeler (R2).

**Stories to have ready**
- *The result that surprised me:* I expected the guard to reduce attack success; the real finding was that exposure, not defense, decides the outcome. I built an exposure funnel (landing, staging, enrichment, gold, agent input) to show it and then attacked the one layer that is always exposed.
- *A mistake and the fix:* I launched a 2.5 h run before sampling whether my "directed reading" switches raised exposure; they did not (12.5% unchanged) and halved benign accuracy. Now I sample a few trials first.
- *A pipeline decision:* contracts reject child car-seat complaints (969 rows, different component vocabulary) on purpose; the data-quality agent's `unseen_component` category is a real case.
- *Engineering:* resumable runner (torn lines, abort after 5 consecutive connection errors, deduped on load), contract-validated enrichment output, pinned model digest, CI on a synthetic fixture.

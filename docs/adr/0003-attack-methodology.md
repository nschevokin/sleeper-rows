# ADR 0003: attack methodology
- Status: accepted.
- Six fixed families x three placements x doses 1/5/25 x 3 seeds, targets split by hash into dev (iterate) and frozen test (report); the matrix defaults to `test`.
- Each trial lands poisoned rows through the real `land()`, recomputes staging and gold, and runs the agent twice: attacked and matched control (same rows, benign equal-length text, no canary). Only the payload's effect counts.
- Success is computed from outputs and warehouse state (`attacks/success.py`); survival is logged per layer (landing, staging, enrichment, gold, agent input, quarantine).
- Statistics: cluster bootstrap over targets, Wilson intervals, exact McNemar vs the `none` defense.
- Decision: no automated payload generator. Adaptive attacks are a stated limitation, not a claim.

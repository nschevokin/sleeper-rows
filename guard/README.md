# taintguard

Lineage-based taint tracking and tool-call policy for LLM agents that read warehouse data.

```python
from taintguard import load_contracts
from taintguard.lineage import analyze_query
from agents.guard_adapter import make_guard_catalog  # pipeline steps -> Catalog

contracts = load_contracts("contracts")
catalog = make_guard_catalog(contracts, label_window_days=120)
q = analyze_query("SELECT make, top_summary FROM gold_trends", catalog)
q.tiers_for(2)  # per output column: TRUSTED < STRUCTURED < UNTRUSTED
```
Untrusted text is never shown to a tool-calling model: it goes to a quarantined extractor (closed schema, no tools), a deterministic shape view, or is withheld. Closed tool arguments use capability checks; free text is checked for unseen contacts; numbers in answers are checked against non-untrusted cells.

Design and test spec: `docs/adr/0004-taint-guard-design.md`. Run the tests: `uv run pytest guard/tests`.

## What it does not stop (residuals)
| # | Residual |
|---|---|
| R1 | Volume poisoning: inflating counts with benign-looking rows |
| R2 | In-range typed values chosen by the attacker (severity, component) |
| R3 | Tampering that lands on another real cell |
| R4 | Free-text paraphrase with no contact token |
| R5 | Declarations the library cannot verify (python-written models) |
| R6 | Over-taint: refused queries, withheld cells (utility cost) |
| R7 | Disruption (step-budget exhaustion) |
| R8 | Shape run-length channel (few bits) |

The tests marked `GAP` assert these misses so they change if a gap is ever closed.

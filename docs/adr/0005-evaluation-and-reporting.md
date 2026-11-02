# ADR 0005: evaluation and reporting
- Status: accepted.
- `eval.cli run|report|all` is the single entry point; config in `eval/configs/*.yaml`, never flags. Trials append to `trials.jsonl` (resumable); errors are rows, not crashes.
- Reports carry banners for stub models and synthetic data. A stub result is never described as a finding.
- Baseline (benign) runs per defense report the utility cost: blocks, flags, extraction loss, latency.
- Scores come from the warehouse and traces; there is no LLM judge.

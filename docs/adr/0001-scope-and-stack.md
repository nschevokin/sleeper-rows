# ADR 0001: scope and stack
- Status: accepted. Date: 2026-10-27.
- **Scope:** NHTSA complaints (plan option B), one-command rebuild from a pinned snapshot (`snapshot.yaml` with checksums, scope and seed).
- **Stack:** Dagster (orchestration), Iceberg via PyIceberg SQL catalog (snapshots allow time-travel diffs of poisoned landings), Polars + DuckDB SQL (transforms), sqlglot (lineage), Pydantic + YAML (contracts), JSONL event log, static JS + canvas viewer, Ollama open models pinned by digest at temperature 0.
- **Why local-first:** the whole study must reproduce on a laptop with no paid services.
- **Consequence:** model capability is limited to small open models; see limitations.

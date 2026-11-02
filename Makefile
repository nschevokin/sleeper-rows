# Targets: fixture ingest run attack eval observatory test lint typecheck check ci clean
.PHONY: paper setup fixture ingest run attack eval observatory test lint typecheck check ci clean
# One target per stage. Every stage reads configuration from files, never from flags.
# MODE=stub (default, no LLM needed) | replay | ollama (laptop; needs `ollama serve`).
MODE ?= stub
SNAPSHOT ?= .fixture/snapshot.yaml
WAREHOUSE ?= .warehouse

setup:
	uv sync --all-packages

fixture:
	uv run python -m fixtures.make_fixture --size tiny --out .fixture/data

ingest:
	uv run python -m pipeline.cli ingest --snapshot $(SNAPSHOT) --warehouse $(WAREHOUSE)

MODEL ?=
run: ingest
	uv run python -m pipeline.cli build --snapshot $(SNAPSHOT) --warehouse $(WAREHOUSE) --mode $(MODE) $(if $(MODEL),--model $(MODEL))

# The attack matrix builds its own in-memory environment from the snapshot named in the config.
attack:
	uv run python -m eval.cli run --config eval/configs/$(MODE).yaml

eval:
	uv run python -m eval.cli all --config eval/configs/$(MODE).yaml

observatory:
	uv run python -m observatory.compact --events results/$(MODE)/events --out observatory/replays

test:
	uv run pytest

lint:
	uv run ruff check . && uv run ruff format --check .

typecheck:
	uv run mypy

check: lint typecheck test

ci: check
	$(MAKE) eval MODE=stub

clean:
	rm -rf .warehouse results observatory/replays .pytest_cache .mypy_cache .ruff_cache

paper:  ## build the write-up draft (needs a LaTeX install; uses matplotlib)
	python3 paper/make_figures.py && cd paper && latexmk -pdf -interaction=nonstopmode main.tex

# Repository Guidelines

## Codebase Knowledge Base
Concise LLM-optimized documentation of the entire angr codebase lives in `docs/agents/`. Start with `docs/agents/SYSTEMS.md` (subsystem index), then drill into `SUBSYSTEM_*.md` files for depth, or `FILES.md` for per-file lookup.

## Project Structure & Module Organization
- `angr/`: Core Python package (analyses, procedures, state/engine code). Rust/C helpers live under `angr/rustylib` and the built `unicornlib.*` in `angr/`.
- `tests/`: Unit/integration tests. Many tests need the sibling `binaries` repo cloned next to this repo.
- `native/`: Native code (Rust in `native/angr/`, C/Make for `unicornlib`).
- `docs/`: Sphinx documentation sources.

## Build, Test, and Development Commands
- Create env and install (editable): `pip install -e .` or with extras: `pip install -e .[angrdb,keystone,telemetry]`
- Using uv (recommended if available): `uv sync` (installs dev + extras from `pyproject.toml`).
- Lint/format: `ruff check . --fix` and `black .` (pre-commit runs both).
- Run tests: `pytest -q` or parallel `pytest -n auto`.
- CLI smoke test: `python -m angr --help` or `angr --help`.

Notes: Build requires Python 3.10+, Rust toolchain, `setuptools-rust`, and `pyvex`. Native `unicornlib` is built automatically via `make`/`gmake`/`nmake` during install.

## Coding Style & Naming Conventions
- Formatting: Black (line length 120); imports and lint via Ruff. Run `pre-commit run -a` before pushing.
- Indentation: 4 spaces; type hints encouraged. Prefer `from __future__ import annotations` where needed.
- Naming: modules/functions `snake_case`, classes `PascalCase`, constants `UPPER_CASE`.

## Testing Guidelines
- Framework: `unittest` style tests discoverable by pytest. Avoid pytest-specific features in tests.
- External fixtures: clone test binaries beside this repo: `git clone https://github.com/angr/binaries`.
- Location: place tests under `tests/<area>/test_*.py`; keep fast by default; use `tests/perf/` for slow perf tests.

## Commit & Pull Request Guidelines
- Commits: short, imperative subject; optionally prefix scope (e.g., `analyses:`). Reference PR/issue numbers, e.g., `(#5562)`.
- PRs: include clear description, rationale, and links to issues; add tests and update docs when behavior changes. Include before/after snippets, screenshots for CLI/log output if relevant.
- CI hygiene: ensure `ruff` and `black` pass; run `pytest` locally. Avoid committing large binaries—use the `binaries` repo.

## Security & Configuration Tips
- Do not execute untrusted samples by default (`auto_load_libs=False` can reduce risk in examples).
- Keep optional deps minimal; use extras (`[angrdb, keystone, telemetry]`) only when needed.

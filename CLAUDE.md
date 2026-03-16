# CLAUDE.md

## Project Overview

Oxidizer is a Rust decompiler built on top of angr. It generates concise, high-fidelity Rust pseudocode from stripped Rust binaries by recovering high-level Rust abstractions (enums, pattern matching, `?` operator, macros). Published at IEEE S&P 2026 by SEFCOM at Arizona State University.

The Python package name is `angr` (this is a fork of angr with Rust decompilation extensions). The Rust-specific code lives primarily in `angr/rust/`.

## Repository Structure

```
angr/                       # Main Python package
  rust/                     # Oxidizer-specific modules (~80 files)
    analyses/               # Rust-specific analyses (symbol recovery, type DB, version ID)
      flirt_sigs/           # 330 FLIRT signature files for Rust versions
      type_db/              # 55 type database JSON files (Rust 1.39.0–1.93.0)
    optimization_passes/    # Decompilation optimization passes
      macro/                # Macro outliners (format!, vec!, etc.)
      outliners/            # Code outliners (string literals, unwrap, vec ops)
    knowledge_plugins/      # Knowledge base plugins for Rust types
    typehoon/               # Constraint-based type inference engine
    sim_type.py             # Rust-specific type system
    utils/                  # Demangling, calling conventions, AIL utilities
  analyses/                 # Core angr analyses (CFG, decompiler, etc.)
  engines/                  # Execution engines (VEX, AIL, pcode, light)
  procedures/               # SimProcedures for library function modeling
  knowledge_plugins/        # Core knowledge base plugins
  state_plugins/            # State plugins (memory, solver, heap)
native/                     # Native code
  angr/                     # Rust PyO3 library (rustylib: fuzzer, icicle, segmentlist)
  unicornlib/               # Unicorn emulator wrapper (C++)
tests/                      # Python test suite (pytest)
binaries/                   # Test binaries (FakeCrypt-stripped)
docs/                       # Sphinx documentation
```

## Build & Development

### Toolchain Requirements
- **Python**: >= 3.10
- **Rust**: 1.88 (pinned in `rust-toolchain.toml`)
- **C++ compiler**: Required for unicornlib

### Local Setup
```bash
pip install setuptools setuptools-rust rust-demangler==1.0
pip install git+https://github.com/angr/archinfo.git@84ad167543028b32e170d3659650707b3866185c
pip install git+https://github.com/angr/claripy.git@8b890bb13fe743bfdbaae119062631db4f10047b
pip install git+https://github.com/angr/pyvex.git@3f92fece7147e91cea401e14a3936f20860a402e
pip install git+https://github.com/angr/cle.git@ce3333d0e1e72936fdbb75eefd70299ead4fb998
pip install --no-build-isolation -e .
```

### Docker
```bash
docker build -t oxidizer .
docker run -it --rm oxidizer python demo.py
```

### Running the Demo
```bash
python demo.py   # Decompiles binaries/FakeCrypt-stripped at 0x455300
```

## Testing

```bash
# Python tests
pytest tests/

# Rust tests
cargo test --release

# Rust linting/formatting
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## Code Style & Linting

### Python
- **Formatter**: black (line-length 120, target py310)
- **Linter**: ruff (line-length 120, extended rules: B, C4, FURB, PIE, RET, RSE, RUF, SIM, UP)
- **Required import**: `from __future__ import annotations` in every file (enforced by ruff isort)
- **Pre-commit hooks**: validate-pyproject, black, ruff, pyupgrade (--py310-plus), trailing-whitespace, mixed-line-ending

### Rust
- **Clippy**: all warnings + cargo warnings treated as errors (`-D warnings`)
- **Format**: rustfmt (standard)

## Key Architecture Concepts

### Rust Decompilation Pipeline (in order)
1. `CFGFast(normalize=True)` — Build control flow graph
2. `CompleteCallingConventions(recover_variables=False)` — Recover calling conventions
3. `RustSymbolRecovery()` — FLIRT-based Rust standard library recovery + version detection
4. `TypeDBLoader()` — Load version-specific struct/enum/function type databases
5. `Decompiler(func)` — Decompile with Rust-specific optimization passes

### Entry Points
- **Python CLI**: `angr.__main__:main` (`angr [options] binary decompile|disassemble`)
- **Python API**: `angr.Project(binary, is_rust_binary=True)`
- **Rust native library**: `angr.rustylib` (PyO3 cdylib with fuzzer, icicle, segmentlist modules)

## CI

Runs on push to `master` and PRs:
- Python tests via `angr/ci-settings` shared workflow
- Rust clippy + fmt check
- Rust tests (cross-platform: Linux, macOS, Windows)
- Smoke tests for installation on Windows and macOS
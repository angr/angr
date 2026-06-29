# Clarirs Development Guide

Clarirs is a Rust reimplementation of [claripy](https://github.com/angr/claripy), designed as a high-performance SMT solver abstraction for the [angr](https://github.com/angr/angr) symbolic execution framework. It provides Python bindings via PyO3 while maintaining the performance benefits of Rust.

## Architecture Overview

### Crate Structure
```
crates/
├── clarirs_core/       # Core AST, algorithms, and solver traits
├── clarirs_num/        # Numeric primitives (BitVec, Float)
├── clarirs_py/         # Python bindings (builds as 'claripy' module)
├── clarirs_z3/         # Z3 solver implementation (links the z3-sys crate)
└── clarirs-vsa/        # Value Set Analysis solver
```

**Key Design Principle**: Core logic in `clarirs_core` is solver-agnostic. Concrete solver implementations (`clarirs_z3`, `clarirs-vsa`) implement the `Solver<'c>` trait.

### AST System

**Lifetime-based Context**: All ASTs carry a `'c` lifetime tied to a `Context<'c>`. The context owns caching infrastructure and ensures AST nodes from different contexts never mix.

```rust
// ASTs are reference-counted Arc<AstNode<'c, Op>> with cached hashing
pub type BoolAst<'c> = AstRef<'c, BooleanOp<'c>>;
pub type BitVecAst<'c> = AstRef<'c, BitVecOp<'c>>;
```

**Hash Consing**: `Context` uses `AstCache` to deduplicate identical AST nodes. Hashes include operation, children, and annotations. See `crates/clarirs_core/src/context.rs::make_bool_annotated`.

**Annotations**: ASTs can carry metadata (`StridedInterval`, `RegionAnnotation`, etc.) that survive transformations if marked `relocatable`. See `crates/clarirs_core/src/ast/annotation.rs`.

### Algorithm Pattern

Algorithms are implemented as traits on AST types:
```rust
pub trait Simplify<'c>: Sized {
    fn simplify(&self) -> Result<Self, ClarirsError>;
}
```

Common algorithms in `crates/clarirs_core/src/algorithms/`:
- `simplify/`: Multi-pass constant folding and algebraic simplification
- `excavate_ite/`: Hoist ITE conditions to top level
- `replace.rs`: AST substitution with type coercion (BV ↔ FP)
- `canonicalize.rs`: Structural matching for equivalence checking

## Development Workflows

### Building & Testing

**Rust (Cargo Workspace)**:
```bash
cargo build --all-features           # Build all crates
cargo test                           # Run Rust tests
cargo clippy --all-features -- -D warnings
```

**Python Bindings (via uv)**:
```bash
uv sync                              # Install/sync dependencies (creates .venv)
uv sync --force-reinstall            # Force reinstall all packages
source .venv/bin/activate            # Activate virtual environment
pytest crates/clarirs_py/tests/      # Run Python tests
```

**CI Requirements**: All builds require Z3 compilation via CMake + Ninja. Set `CMAKE_GENERATOR=Ninja` and `CC=clang` for optimal caching with sccache. See `.github/workflows/ci.yml`.

### Python Bindings Convention

The `clarirs_py` crate builds to module name `claripy` (see `Cargo.toml: [lib] name = "claripy"`).

**PyO3 Patterns**:
- AST wrappers (BV, Bool, FP) implement `__new__` with signature `(op, args, annotations=None)`
- Factory functions use `add_pyfunctions!` macro (see `crates/clarirs_py/src/macros.rs`)
- Submodules registered via `import_submodule` helper to install in `sys.modules`

**Type Coercion**: `CoerceBV`, `CoerceBool` extract Rust types or Python ints. Example:
```rust
pub enum CoerceBV {
    BV(Py<BV>),
    Int(BigInt),  // Accept Python int where BV expected
}
```

### Testing Strategy

**Python Tests**: `crates/clarirs_py/tests/test_*.py` use `unittest` with two backends:
```python
self.z3 = claripy.SolverZ3()
self.concrete = claripy.SolverConcrete()
```
Tests verify symbolic expressions against Z3 and concrete values match expected results. Run with:
```bash
source .venv/bin/activate
pytest crates/clarirs_py/tests/      # Run all Python tests
pytest crates/clarirs_py/tests/test_bv_ops.py  # Run specific test file
```

## Critical Patterns

### Solver Trait Implementation

All solvers implement `Solver<'c>` from `crates/clarirs_core/src/solver.rs`:
```rust
pub trait Solver<'c>: Clone + HasContext<'c> {
    fn add(&mut self, constraint: &BoolAst<'c>) -> Result<(), ClarirsError>;
    fn satisfiable(&mut self) -> Result<bool, ClarirsError>;
    fn eval_bitvec(&mut self, expr: &BitVecAst<'c>) -> Result<BitVecAst<'c>, ClarirsError>;
    // ... min/max, multiple solutions, etc.
}
```

**Z3 Solver** (`crates/clarirs_z3/src/solver.rs`): Uses thread-local `Z3_CONTEXT` to convert clarirs ASTs to Z3 via `AstExtZ3` trait. Always creates a fresh solver per query.

**VSA Solver** (`crates/clarirs-vsa/src/solver.rs`): Stateless—uses `Reduce` trait to compute strided intervals without constraint tracking.

### Error Handling

Use `ClarirsError` from `crates/clarirs_core/src/error.rs`. Conversion from `BitVecError` and `PoisonError` is automatic. Python bindings map to custom exception hierarchy (`ClaripyError`, `UnsatError`, etc.).

### Z3 Bindings Build Process

`clarirs_z3` links against the upstream [`z3-sys`](https://crates.io/crates/z3-sys)
crate with its `gh-release` feature, which downloads a prebuilt static Z3 library
(Z3 4.16.0 by default; override with `Z3_SYS_Z3_VERSION`) from the official
Z3Prover GitHub releases — no system Z3 install, git submodule, or local Z3
compilation. The backend (`rc.rs`/`solver.rs`/`astext.rs`) calls the `z3-sys` C
API directly (`use z3_sys::*;`). Two upstream conventions are handled at the call
sites: pointer constructors return `Option<NonNull<_>>` (funneled through
`RcAst::try_from(Option<_>)` or the `require()` helper in `lib.rs`), and
`Z3_lbool` is an integer compared against the `Z3_L_*` constants.

Requires network access at build time to fetch the Z3 release (cached in the build
dir afterward); CI sets `READ_ONLY_GITHUB_TOKEN` to avoid GitHub API rate limits.
sccache caches Rust compilation.

## Claripy Compatibility Notes

**Module name**: Python imports as `import claripy`, not `clarirs`.

**Function naming**: Factory functions match claripy conventions (e.g., `BVS`, `BVV`, `BoolS` for symbolic/value constructors).

**Intentional divergences**: Clarirs focuses on angr's usage patterns. Some claripy features (solver frontends beyond Z3/VSA, certain backends) are not implemented.

## Key Files to Reference

- `crates/clarirs_core/src/prelude.rs`: Imports for all AST types and traits
- `crates/clarirs_py/src/lib.rs`: Python module entrypoint with all exports
- `crates/clarirs_core/src/cache.rs`: Hash consing implementation
- `crates/clarirs_z3/src/astext.rs`: Clarirs → Z3 AST conversion
- `.github/workflows/ci.yml`: Build requirements and platform-specific setup

## Edition & Toolchain

- **Rust Edition**: 2024 (stable)
- **Toolchain**: Rust 1.88 (see `rust-toolchain.toml`)
- **Python**: 3.12+ (PyO3 0.27+)
- **Package Manager**: uv for Python dependencies

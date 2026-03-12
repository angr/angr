# Oxidizer: Toward Concise and High-fidelity Rust Decompilation

Oxidizer is a Rust decompiler built on top of [angr](https://github.com/angr/angr) that generates concise and high-fidelity Rust pseudocode from stripped Rust binaries. Unlike existing C-oriented decompilers, Oxidizer is specifically designed to handle Rust's unique compilation patterns and recover high-level Rust abstractions such as enums, pattern matching, error propagation (`?` operator), and macros (`println!`, `format!`, `panic!`, etc.).

## Publication

**Oxidizer: Toward Concise and High-fidelity Rust Decompilation**
Yibo Liu, Zion Leonahenahe Basque, Arvind S. Raj, Chavin Udomwongsa, Chang Zhu, Jie Hu, Changyu Zhao, Fangzhou Dong, Adam Doupé, Tiffany Bao, Yan Shoshitaishvili, Ruoyu Wang
*IEEE Symposium on Security and Privacy (S&P), 2026*

## Overview

Modern C decompilers (Hex-Rays, Ghidra, Binary Ninja, angr) produce verbose and inaccurate output when decompiling Rust binaries, because they fail to recover high-level Rust abstractions from low-level implementations. Oxidizer addresses this by implementing a Rust-specific decompilation pipeline:

1. **Binary-level Analysis** — Identifies the Rust compiler version via FLIRT signatures (supporting Rust 1.45.2–1.88.0), locates standard library functions, and loads version-specific struct/function type databases.

2. **fCFG Simplification (without Types)** — Removes extraneous code introduced by Rust's automatic resource management (`drop_in_place`, `__rust_dealloc`) and compiler-inserted security checks (bounds checking, etc.).

3. **Rust Type Inference** — Performs inter-procedural function prototype inference to recover struct/enum return types and argument types, enhanced with a constraint-based type inference algorithm (Retypd) extended with enum type support.

4. **fCFG Simplification (with Types)** — Recovers struct and enum initializations, outlines common macros (`println!`, `format!`, `write!`, `panic!`, etc.), simplifies deref coercions, and more.

5. **Structuring** — Converts the simplified fCFG into high-level Rust control flow constructs, including `match`/`if let` pattern matching and `?` error propagation.

6. **Rust Pseudocode Generation** — Outputs structured, human-readable Rust pseudocode.

## Key Results

Evaluated on 28 popular Rust projects from GitHub across six optimization levels and two Rust compiler versions:

- **15% fewer lines of code** and **7% lower cyclomatic complexity** compared to the best-performing C decompiler
- **Only tool capable of recovering Rust enums and macros**
- Outperforms angr, Hex-Rays, Ghidra, and Binary Ninja on most conciseness and fidelity metrics
- Human study (37 participants): **28% higher accuracy** and **20% faster task completion** compared to Hex-Rays, with an average user rating of **4.49/5** (vs. 2.61/5 for Hex-Rays)

## Quick Start
1. Clone the repository and install dependencies:
```bash
pip install -U git+https://github.com/angr/archinfo.git@84ad167543028b32e170d3659650707b3866185c
pip install -U git+https://github.com/angr/claripy.git@8b890bb13fe743bfdbaae119062631db4f10047b
pip install -U git+https://github.com/angr/pyvex.git@3f92fece7147e91cea401e14a3936f20860a402e
pip install -U git+https://github.com/angr/cle.git@ce3333d0e1e72936fdbb75eefd70299ead4fb998
pip install --no-build-isolation git+https://github.com/bluesadi/oxidizer.git
```
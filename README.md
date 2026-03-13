# Oxidizer: Toward Concise and High-fidelity Rust Decompilation

Oxidizer is a Rust decompiler built on top of [angr](https://github.com/angr/angr) that generates concise and high-fidelity Rust pseudocode from stripped Rust binaries. 
Unlike existing C-oriented decompilers, Oxidizer is specifically designed to handle Rust's unique compilation patterns and recover high-level Rust abstractions such as enums, pattern matching, error propagation (`?` operator), and macros (`println!`, `format!`, `panic!`, etc.).
It is brought to you by [SEFCOM at Arizona State University](https://sefcom.asu.edu).

*We will be working on merging Oxidizer to the master branch of [angr](https://github.com/angr/angr).*

## Publication

**Oxidizer: Toward Concise and High-fidelity Rust Decompilation**
Yibo Liu, Zion Leonahenahe Basque, Arvind S. Raj, Chavin Udomwongsa, Chang Zhu, Jie Hu, Changyu Zhao, Fangzhou Dong, Adam Doupé, Tiffany Bao, Yan Shoshitaishvili, Ruoyu Wang
*IEEE Symposium on Security and Privacy (S&P), 2026*. (To appear)

## Overview

Modern C decompilers (Hex-Rays, Ghidra, Binary Ninja, angr) produce verbose and inaccurate output when decompiling Rust binaries, because they fail to recover high-level Rust abstractions from low-level implementations. Oxidizer addresses this by implementing a Rust-specific decompilation pipeline:

1. **Binary-level Analysis** — Identifies the Rust compiler version via FLIRT-based function match rate analysis, recovers standard library functions, and loads version-specific struct/enum/function type databases (supporting Rust 1.39.0–1.93.0).

2. **fCFG Simplification (without Types)** — Removes extraneous code introduced by Rust's automatic resource management (`drop_in_place`, `__rust_dealloc`) and compiler-inserted security checks (bounds checking, etc.).

3. **Rust Type Inference** — Performs inter-procedural function prototype inference to recover struct/enum return types and argument types including `Option<T>` and `Result<T, E>`, enhanced with a constraint-based type inference algorithm (Retypd) extended with enum type support.

4. **fCFG Simplification (with Types)** — Recovers struct and enum initializations, outlines common macros (`println!`, `format!`, `write!`, `panic!`, etc.), simplifies deref coercions, and more.

5. **Structuring** — Converts the simplified fCFG into high-level Rust control flow constructs, including `match`/`if let` pattern matching and `?` error propagation.

6. **Rust Pseudocode Generation** — Outputs structured, human-readable Rust pseudocode.

## Quick Start
### Docker
1. Build the Docker image:
```bash
git clone https://github.com/sefcom/oxidizer.git
cd oxidizer
docker build -t oxidizer .
```
2. Run the demo on a stripped Rust binary:
```bash
docker run -it --rm oxidizer python demo.py
```

### Local Setup
1. Clone the repository and install dependencies:
```bash
git clone https://github.com/sefcom/oxidizer.git
pip install setuptools setuptools-rust
pip install rust_demangler==1.0
pip install git+https://github.com/angr/archinfo.git@84ad167543028b32e170d3659650707b3866185c
pip install git+https://github.com/angr/claripy.git@8b890bb13fe743bfdbaae119062631db4f10047b
pip install git+https://github.com/angr/pyvex.git@3f92fece7147e91cea401e14a3936f20860a402e
pip install git+https://github.com/angr/cle.git@ce3333d0e1e72936fdbb75eefd70299ead4fb998
cd oxidizer
pip install --no-build-isolation -e .
```

2. Run the demo on a stripped Rust binary:
```bash
python demo.py
```

### Output
```rust
fn sub_455300(a0: i64, a1: i64, a2: i64, a3: i64) -> u32 {
    let v0: struct4;  // [bp-0x818]
    let v2: Result<struct4, struct8>;  // [bp-0x810]
    let v3: struct24;  // [bp-0x800], Other Possible Types: struct8
    let v4: u64;  // [bp-0x7f8]
    let v5: u64;  // [bp-0x7f0]
    let v6: u64;  // [bp-0x7e8]
    let v7: struct4;  // [bp-0x7d8]
    let v8: Result<struct4, struct8>;  // [bp-0x7b8], Other Possible Types: struct960
    let v9: struct4;  // [bp-0x7b4]
    let v10: Result<struct960, struct16>;  // [bp-0x3f8]
    let v12: u64;  // rax
    let v13: u64;  // rdx
    let v14: u64;  // rdx
    let v15: Option<struct16>;  // rbx
    let v18: u32;  // eax

    v6 = a0;
    v2 = sub_455ee0(a0, a1);
    if let Ok(v0) = v2 {
        v3 = struct24 {
            field_0: 0
            field_8: ""
        };
        v12 = sub_4af4e0(&v0, &v3) as u64;
        if v12 {
            sub_454c60(v12, v13);
        } else {
            sub_454c60(0, v14);
            v3 = sub_451f90((9223372036854775792 & v5) + 16, 0);
            v8 = sub_454ec0(a2);
            v10 = sub_455220(&v8, a3);
            v15 = sub_455010(&v10, v4, v5, v5) as u64;
            match v15 {
                Some(_) => {
                    v8 = sub_455f30(v6, a1);
                    match v8 {
                        Err(_) => {
                            sub_454c90(&v8);
                        },
                        Ok(v7) => {
                            sub_454c70(sub_4560d0(&v7, v15, v14));
                        },
                    }
                },
                None => {
                    eprintln!("[!] Encryption failed for {:?}: {:?}", &v6, &v1);
                },
            }
        }
        return v18;
    }
}
```
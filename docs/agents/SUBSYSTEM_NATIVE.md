# Native Modules (Rust + C)

High-performance native code under `native/`, exposed to Python via PyO3 (`angr/rustylib/`).

## Rust Modules (`native/angr/src/`)

### Icicle (`icicle.rs`, `rustylib/icicle.pyi`)
Concrete VM emulator (adapted from icicle-emu). Used by `IcicleEngine` for fast concrete-only execution.

- `Icicle` — main class: `new(arch)`, `step(count)`, `run()`, `run_until(addr)`
- CPU state: `read_reg(name)`, `write_reg(name, val)`, `set_pc(addr)`
- Memory: `mem_map(addr, size, perm)`, `mem_read(addr, size)`, `mem_write(addr, data)`, `mem_unmap(addr, size)`
- Control: `add_breakpoint(addr)`, `remove_breakpoint(addr)`, `set_extra_stop_points(addrs)`
- Coverage: AFL-style edge hitmap via `edge_hitmap` state plugin
- Block tracing: records executed block addresses
- Returns `VmExit` enum (Halt, Breakpoint, UnhandledException, etc.) with `ExceptionCode`

### Fuzzer (`fuzzer.rs`, `rustylib/fuzzer.pyi`)
LibAFL-based fuzzer with Havoc mutations and coverage-guided feedback.

- `Fuzzer` — `new(icicle, corpus, monitor)`, `fuzz(iterations)`
- `InMemoryCorpus` / `OnDiskCorpus` — testcase storage
- `ClientStats` — coverage/execution statistics
- Monitor callbacks integrate with angr's exploration framework

### Automaton (`automaton/`, `rustylib/automaton.pyi`)
Finite automaton construction for pattern matching (used internally for string/regex analysis).

- `EpsilonNFA` — build with `add_state()`, `add_transition()`, `add_epsilon()`
- `DeterministicFiniteAutomaton` — from subset construction: `from_nfa(nfa)`, `minimize()`
- `State`, `Symbol`, `Epsilon` — core types
- `to_networkx()` — export to NetworkX graph for integration with angr analyses

### SegmentList (`segmentlist.rs`)
RangeMap-backed segment tracking by address range. Used for efficient memory region bookkeeping.

- `SegmentList` — `add(start, end, tag)`, `query(addr)`, `remove(start, end)`
- `Segment` — `start`, `end`, `tag`

## C/C++ Native (`native/unicornlib/`)
Unicorn engine wrapper for `SimEngineUnicorn`. Built via Make/CMake.

- `sim_unicorn.cpp` — main Unicorn integration: state sync, memory mapping, stop-point checking
- `procedures.cpp` — procedure-level hooks
- Vendored Unicorn headers for arm, arm64, mips, x86, riscv, ppc, s390x, m68k, sparc, tricore

# Core Subsystem

## Key Files
- project.py — `Project`: main entry; loads binary via CLE, wires arch/engines/analyses/SimOS
- factory.py — `AngrObjectFactory`: creates blocks, states, SimulationManagers, Callables
- sim_state.py — `SimState`: one symbolic state; PluginHub holding regs/mem/solver/etc.
- sim_manager.py — `SimulationManager`: manages stashes of states; stepping/exploration
- knowledge_base.py — `KnowledgeBase`: container for analysis results (functions, CFG, types, xrefs)
- block.py — `Block`: wraps lifted VEX IRSB; `.capstone`, `.vex`, `.instructions`
- errors.py — all exception classes (`AngrError` tree + `SimError` tree)

## Project
- `Project(thing)` — path, stream, or `cle.Loader`
- Key attrs: `.loader`, `.arch`, `.factory`, `.kb`, `.simos`, `.entry`
- `load_shellcode(bytes, arch)` — quick-load raw bytes
- Hooking: `.hook(addr, proc)`, `.unhook(addr)`, `.is_hooked(addr)`, `.hooked_by(addr)`

## Factory
- `.block(addr)` — lift a `Block`
- `.blank_state()` / `.entry_state()` / `.full_init_state()` / `.call_state(addr, *args)`
- `.simulation_manager(state)` / `.simgr(state)`
- `.callable(addr, prototype=...)` — symbolic function invocation
- `.successors(state)` — run engine, get `SimSuccessors`

## SimState
- Inherits `PluginHub[SimStatePlugin]`; plugins loaded on access
- Key plugins: `.regs`, `.mem`, `.memory`, `.registers`, `.solver`, `.inspect`, `.posix`, `.fs`, `.callstack`, `.scratch`, `.history`
- `.copy()`, `.merge(others)`, `.step()`

## SimStateOptions / sim_options
- `sim_state_options.py` — `SimStateOptions` set-like container
- `sim_options.py` — constants: `SYMBOLIC`, `LAZY_SOLVES`, `TRACK_CONSTRAINTS`, `DO_CCALLS`, etc.
- Presets: `o.refs` (track actions), `o.unicorn` (Unicorn engine)

## SimulationManager
- Stashes: `active`, `deadended`, `errored`, `unsat`, `stashed`, `pruned`, `unconstrained`
- `.step()` — advance one block; `.explore(find=, avoid=)` — run until found
- `.use_technique(tech)` — attach `ExplorationTechnique`
- `.move(from_stash, to_stash, filter_func=)`

## KnowledgeBase
- `project.kb` — default instance; plugin-based
- Key plugins: `.functions`, `.cfgs`, `.types`, `.xrefs`, `.variables`, `.defs`, `.propagations`, `.decompilations`, `.rtdb`

## Supporting Modules
- codenode.py — `BlockNode`, `HookNode`, `SyscallNode` for CFG graphs
- code_location.py — `CodeLocation(block_addr, stmt_idx)` identifies a program point
- sim_type.py — `SimType` hierarchy: `SimTypeInt`, `SimTypePointer`, `SimTypeFunction`, `SimStruct`, `SimTypeArray`
- sim_variable.py — `SimVariable`: `SimRegisterVariable`, `SimStackVariable`, `SimMemoryVariable`, `SimTemporaryVariable`
- callable.py — `Callable`: call binary function symbolically
- emulator.py — `Emulator`: concrete-only wrapper
- serializable.py — `Serializable`: protobuf base class
- keyed_region.py — `KeyedRegion`: SortedDict-backed variable location map
- annocfg.py — `AnnotatedCFG`: CFG slice with whitelists
- blade.py — `Blade`: backward slicer on CFG DiGraph
- slicer.py — `SimSlicer`: intra-IRSB symbolic slicer
- state_hierarchy.py — `StateHierarchy`: DAG of state histories
- vaults.py — `Vault`/`VaultShelf`/`VaultDir`: state persistence by UUID
- llm_client.py — `LLMClient`: LLM integration

## Error Hierarchy
- `AngrError` — `AngrValueError`, `AngrCFGError`, `AngrAnalysisError`, `AngrDecompilationError`, ...
- `SimError` — `SimStateError` (`SimMemoryError`, `SimMergeError`), `SimSolverError` (`SimUnsatError`), `SimEngineError` (`SimProcedureError`), `SimUnsupportedError`, ...

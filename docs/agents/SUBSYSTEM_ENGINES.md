# Engines Subsystem

All under `engines/`. Engines execute one step on a `SimState`, producing `SimSuccessors`.

## Core Dispatch (Mixin Chain)

`UberEngine` composes all via Python MRO. Each mixin's `process_successors()` checks applicability, else calls `super()`.

**MRO (first wins):** SimEngineFailure > SimEngineSyscall > HooksMixin > SimEngineUnicorn > SuperFastpathMixin > TrackActionsMixin > SimInspectMixin > HeavyResilienceMixin > SootMixin > AILMixin > HeavyVEXMixin

- engine.py — `SimEngine`: abstract base
- successors.py — `SimSuccessors` (`.flat_successors`, `.unsat_successors`, `.unconstrained_successors`) + `SuccessorsEngine` dispatch mixin
- failure.py — `SimEngineFailure`: handles `Ijk_EmFail`, `Ijk_MapFail`, `Ijk_Sig*`, `Ijk_Exit`
- hook.py — `HooksMixin`: looks up `project._sim_procedures`, runs `SimProcedure`
- procedure.py — `ProcedureMixin`: `process_procedure()` executes a `SimProcedure`
- syscall.py — `SimEngineSyscall`: triggers on `Ijk_Sys*`; resolves via `project.simos`
- unicorn.py — `SimEngineUnicorn`: fast concrete via Unicorn; falls back on symbolic
- concrete.py — `ConcreteEngine`: GDB/avatar2 hardware-in-the-loop
- icicle.py — `IcicleEngine`: Rust-based concrete VM (via `rustylib.icicle`); supports breakpoints, block tracing, AFL-style edge hitmap coverage, Cortex-M thumb mode. Faster alternative to Unicorn for concrete-only execution

## VEX Engine (`vex/`)

Two variants: **Heavy** (full symbolic, runtime) and **Light** (no state, static analysis).

- light/light.py — `VEXMixin` base: dispatches VEX IR stmts/exprs via handler tables
- heavy/heavy.py — `HeavyVEXMixin`: lifts IRSB, steps stmts, creates successors
- heavy/actions.py — `TrackActionsMixin`: records `SimAction`s
- heavy/inspect.py — `SimInspectMixin`: breakpoint callbacks on mem/reg access
- heavy/dirty.py — dirty helper dispatch
- heavy/resilience.py — `HeavyResilienceMixin`: catches errors, adds error successors
- heavy/concretizers.py — concretization for symbolic addresses
- heavy/super_fastpath.py — `SuperFastpathMixin`: skips symbolic ops when possible
- lifter.py — VEX lifting (binary → IRSB); `VEX_IRSB_MAX_SIZE=400`, `VEX_IRSB_MAX_INST=99`
- claripy/irop.py — VEX IR op implementations (arithmetic, SIMD) as claripy ops
- claripy/ccall.py — VEX ccall helpers (condition codes, FP status)
- claripy/datalayer.py — symbolic memory/register reads

## Light Engine (`light/`)

Architecture-independent abstract interpretation, no `SimState`.

- engine.py — `SimEngineLightVEXMixin`, `SimEngineLightAILMixin`; also `Nostmt` (skip stmt processing) and `Noexpr` (skip expr processing) variants for specialized static analyses
- data.py — data container types

VEX light also has: vex/light/resilience.py (`VEXResilienceMixin`) and vex/light/slicing.py (`VEXSlicingMixin`).

## AIL Engine (`ail/`)

Two modes: **Light** (no SimState, for static analyses like RDA/propagator) and **SimState** (full symbolic execution on AIL IR, for testing/validating decompiler output).

- engine_light.py — `SimEngineLightAILMixin` (static); `SimEngineAILSimState` (full symbolic execution on decompiled AIL)
- engine_successors.py — AIL successor generation
- callstack.py — call stack tracking
- setup.py — AIL engine setup/initialization

## P-Code Engine (`pcode/`)

Alternative lifter using GHIDRA's Sleigh/P-Code. Optional dependency.

- engine.py (`HeavyPcodeMixin`), lifter.py, behavior.py, emulate.py
- `UberEnginePcode` in `__init__.py` (only if pypcode installed)

Alternative compositions: `UberEnginePcode` (P-Code), `UberIcicleEngine` (icicle.py, concrete)

## Soot/Java Engine (`soot/`)

- engine.py — `SootMixin`: main Soot execution
- expressions/, statements/, values/ — IR element handlers
- field_dispatcher.py, method_dispatcher.py — field/method resolution

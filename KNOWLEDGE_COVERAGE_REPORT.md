# Knowledge Base Coverage Analysis Report

**Date:** 2026-02-23
**Scope:** `docs/agents/` vs actual codebase content
**Result:** The knowledge base covers ~95% of the codebase by file count, but has significant depth/accuracy gaps in several areas.

---

## Executive Summary

The knowledge base (16 SUBSYSTEM docs + FILES.md + AGENTS.md) is impressively comprehensive in breadth. FILES.md alone references ~700+ files with only 4 discrepancies. However, the analysis found **3 categories of gaps**:

1. **Stale/incorrect entries** caused by recent code changes (2 items, one critical)
2. **Entirely missing subsystems** not documented anywhere (7 items)
3. **Shallow coverage** where something is name-dropped but not explained (6 items)

---

## Category 1: Stale / Factually Wrong (Fix First)

### 1.1 TypeLifter deleted but still documented
- **Severity:** CRITICAL (factually wrong)
- **What happened:** PR #6173 (most recent commit on master) removed `angr/analyses/typehoon/lifter.py` entirely. `TypeTranslator` now handles both directions.
- **Stale reference:** SUBSYSTEM_RECOVERY.md still lists `lifter.py -- TypeLifter: SimType -> TypeConstant`
- **Fix:** Remove TypeLifter reference, note that TypeTranslator handles both directions.

### 1.2 overflow_builtin_simplifier.py listed but doesn't exist
- **Severity:** LOW (minor phantom entry)
- **Where:** FILES.md line ~202 lists `overflow_builtin_simplifier.py` as an optimization pass, but the file does not exist on disk (likely still on a branch).
- **Fix:** Remove entry from FILES.md.

### 1.3 Call/SideEffectStatement split not reflected
- **Severity:** HIGH (architectural change under-documented)
- **What happened:** PR #6115 split the AIL `Call` statement into `CallExpr` (expression, returns a value) and `SideEffectStatement` (call for side effects only). This was a **70-file refactor** touching virtually every decompiler pass.
- **Current docs:** SUBSYSTEM_AIL.md mentions `SideEffectStatement` exactly once. `CallExpr` is not mentioned at all. FILES.md still describes `Call` without distinguishing the split.
- **Fix:** Update SUBSYSTEM_AIL.md statement/expression hierarchies; update FILES.md entries for `expression.py` and `statement.py`.

---

## Category 2: Entirely Missing Subsystems

### 2.1 Native Rust Modules (fuzzer, icicle, automaton, segmentlist)
- **Severity:** CRITICAL
- **What exists:** Four high-performance Rust modules in `native/angr/src/` with PyO3 bindings exposed via `angr/rustylib/`:
  - **fuzzer** -- LibAFL-based fuzzer with Havoc mutations, corpus management, edge coverage feedback
  - **icicle** -- Concrete VM emulator with CPU state, memory mapping, breakpoints, coverage tracking
  - **automaton** -- Epsilon-NFA/DFA construction, minimization, subset construction, pattern matching
  - **segmentlist** -- RangeMap-backed segment tracking by address range
- **Current docs:** Zero coverage. SUBSYSTEM_ENGINES.md has a one-liner for `IcicleEngine`. The other three modules are not mentioned anywhere.
- **Recommendation:** New `SUBSYSTEM_NATIVE.md` documenting all four modules, their Python APIs (from .pyi stubs), and usage patterns.

### 2.2 CLI (`angr/__main__.py`)
- **Severity:** HIGH
- **What exists:** Full argparse CLI with two commands:
  - `angr decompile` / `angr dec` -- decompile functions (structurer choice, presets, LLM, progress bar, syntax highlighting)
  - `angr disassemble` / `angr dis` -- disassemble functions
- **Current docs:** AGENTS.md mentions `python -m angr --help` as a smoke test. No command reference.
- **Recommendation:** Add CLI reference section to AGENTS.md or SUBSYSTEM_CORE.md.

### 2.3 Corpus Testing Framework (`corpus_tests/`)
- **Severity:** LOW-MEDIUM (specialized audience)
- **What exists:** GitHub Actions pipeline for regression-testing decompiler output against a binary corpus. Includes snapshot diffing, classification scripts, and `act` support for local runs.
- **Current docs:** Not mentioned anywhere.
- **Recommendation:** Brief mention in AGENTS.md testing section.

### 2.4 Semantic Variable Naming (`analyses/decompiler/semantic_naming/`)
- **Severity:** MEDIUM
- **What exists:** 6-file module for context-aware variable naming (call results, pointer usage, sizes, booleans). Part of the decompiler pipeline.
- **Current docs:** SUBSYSTEM_DECOMPILER.md mentions "semantic naming" in the pipeline but FILES.md doesn't list the `semantic_naming/` directory contents.
- **Recommendation:** Add file listings to FILES.md; expand description in SUBSYSTEM_DECOMPILER.md.

### 2.5 Decompilation Notes (`analyses/decompiler/notes/`)
- **Severity:** LOW
- **What exists:** 2-file module for annotating decompilation output with extra context (e.g., deobfuscated strings).
- **Current docs:** Not mentioned.
- **Recommendation:** Add to FILES.md.

### 2.6 Function Outliner (`analyses/outliner/`)
- **Severity:** LOW
- **What exists:** Function outlining analysis.
- **Current docs:** Not mentioned in subsystem docs (listed in FILES.md but not in SUBSYSTEM_ANALYSIS_MISC.md).
- **Recommendation:** Add one-liner to SUBSYSTEM_ANALYSIS_MISC.md.

### 2.7 Enum Type Inference
- **Severity:** MEDIUM
- **What exists:** PR #6033 added `SimTypeEnum` support, enum type constants in typehoon, enum lifting/translation, VRA changes for enum recognition. Test suite at `tests/types/test_enum_*.py`.
- **Current docs:** Not mentioned in decompiler or recovery subsystem docs.
- **Recommendation:** Add to SUBSYSTEM_RECOVERY.md (typehoon section) and note `SimTypeEnum` in SUBSYSTEM_CORE.md SimType hierarchy.

---

## Category 3: Shallow Coverage (Name-Dropped but Not Explained)

### 3.1 Simulation Options (`sim_options.py`)
- **Severity:** HIGH
- **What exists:** 100+ boolean constants controlling symbolic execution behavior, organized into categories: constraint tracking, simplification, symbolic execution, memory, Unicorn engine, resilience, approximation. Plus preset `modes` dict defining `"symbolic"`, `"static"`, `"fastpath"`, `"tracing"`, etc.
- **Current docs:** SUBSYSTEM_CORE.md mentions the file and gives 4 example constants (`SYMBOLIC`, `LAZY_SOLVES`, `TRACK_CONSTRAINTS`, `DO_CCALLS`).
- **What's missing:** The other ~96 options, category explanations, mode presets and when to use them, performance/soundness tradeoffs.
- **Recommendation:** New section in SUBSYSTEM_CORE.md or standalone reference. At minimum, document the mode presets and the most impactful option groups (Unicorn, resilience, approximation).

### 3.2 LLM Integration (`llm_client.py` + decompiler integration)
- **Severity:** MEDIUM
- **What exists:** `LLMClient` class using LiteLLM, configurable via env vars (`ANGR_LLM_MODEL`, `ANGR_LLM_API_KEY`, `ANGR_LLM_API_BASE`). Used by decompiler for variable/function naming refinement. CLI `--llm` flag. Tests in `tests/llm/`.
- **Current docs:** One line in SUBSYSTEM_CORE.md: "llm_client.py -- LLMClient: LLM integration"
- **What's missing:** Configuration guide, env vars, model options, decompiler integration points, CLI flag documentation.
- **Recommendation:** Add configuration section to SUBSYSTEM_CORE.md or SUBSYSTEM_DECOMPILER.md.

### 3.3 FunctionManager LMDB Spilling + RuntimeDb
- **Severity:** MEDIUM
- **What exists:** PR #5976 added LMDB-backed function storage for large binaries: `RuntimeDb` knowledge plugin, `SpillingFunctionDict`, `FuncNode` lightweight graph nodes, `Function.dirty` tracking, configurable cache limits, env var for DB base dir.
- **Current docs:** SUBSYSTEM_KNOWLEDGE.md mentions "SortedDict or LMDB-spilling" and "RuntimeDb" in passing.
- **What's missing:** Architecture explanation (eviction, dirty tracking, serialization pipeline, LMDB integration, FuncNode concept, environment configuration).
- **Recommendation:** Expand SUBSYSTEM_KNOWLEDGE.md functions section.

### 3.4 AIL Symbolic Execution Engine
- **Severity:** MEDIUM
- **What exists:** Full symbolic execution engine for AIL at `angr/engines/ail/` (841-line engine_light.py, engine_successors.py, callstack.py). Enables running the decompiler's IR through the standard symbolic execution framework.
- **Current docs:** SUBSYSTEM_ENGINES.md lists `SimEngineAILSimState` and the files. No explanation of what AIL symbolic execution is for, when to use it, or how it differs from the light AIL engine used in static analyses.
- **Recommendation:** Add purpose/usage paragraph to SUBSYSTEM_ENGINES.md.

### 3.5 SSAilification Internals
- **Severity:** LOW-MEDIUM
- **What exists:** PR #6009 substantially rewrote the ssailification pass: new `Extract`/`Insert` AIL expressions, `PointerDisposition` concept, rewritten stack variable identification, clinic stage reordering.
- **Current docs:** SUBSYSTEM_DECOMPILER.md says "Two sub-passes: TraversalAnalysis, RewritingAnalysis" and lists the files.
- **What's missing:** `PointerDisposition`, stack variable identification logic, `Extract`/`Insert` context and purpose.
- **Recommendation:** Expand ssailification section in SUBSYSTEM_DECOMPILER.md.

### 3.6 Protobuf Serialization Schemas
- **Severity:** LOW
- **What exists:** 5 `.proto` files defining schemas for CFG nodes/edges, functions, code references, variables, xrefs. Used by AngrDB and distributed analysis.
- **Current docs:** SUBSYSTEM_UTILITIES.md has a one-liner listing the proto names. FILES.md lists the `_pb2.py` files.
- **What's missing:** Schema details, message fields, how protobuf integrates with AngrDB serialization, compatibility notes.
- **Recommendation:** Brief schema overview in SUBSYSTEM_UTILITIES.md.

---

## Category 4: Minor Gaps & Nits

| Item | Location | Issue |
|------|----------|-------|
| `mips_gp_setting_simplifier.py` | `decompiler/optimization_passes/` | File exists but not listed in FILES.md |
| `__init__.py`, `__main__.py` | `angr/` root | Not in FILES.md (standard omission for `__init__`, but `__main__` is non-trivial) |
| `SimTypeFd` | `sim_type.py` | New sim type for file descriptors (PR #6122), not documented |
| `SimTypeEnum` | `sim_type.py` | New sim type for enums (PR #6033), not in SimType hierarchy docs |
| Icicle engine features | `engines/icicle.py` | Block tracing, AFL-style edge hitmap, Cortex-M thumb mode, breakpoints -- all undocumented |
| Coverage state plugin | `state_plugins/` | Refactored in PR #6098, not documented |
| `fold_expressions` clinic param | `decompiler/clinic.py` | PR #6066 addition, not in docs |
| `tablespecs.py` | `angr/` root | `StringTableSpec` for argv/envp setup, only a terse FILES.md entry |
| GUI decompilation workflows | `tests/gui/` | Cache + KB integration test patterns, not documented |
| CCall rewriter coverage | `decompiler/ccall_rewriters/` | ARM full coverage and x86 additions not detailed |
| `graph_utils.py` | `angr/` root | Nearly empty file; docs reference it but actual graph utils are in `utils/graph.py` |

---

## FILES.md Accuracy Summary

| Metric | Count |
|--------|-------|
| Files documented in FILES.md | ~700+ |
| Files missing from FILES.md | 4 (`__init__.py`, `__main__.py`, `mips_gp_setting_simplifier.py`, + semantic_naming/ contents) |
| Stale entries (file deleted) | 2 (`overflow_builtin_simplifier.py`, `lifter.py` in typehoon) |
| **Accuracy rate** | **~99.1%** |

---

## Recommended Priority for Updates

### P0 -- Fix Now (factually wrong)
1. Remove TypeLifter from SUBSYSTEM_RECOVERY.md (file deleted in PR #6173)
2. Remove `overflow_builtin_simplifier.py` from FILES.md (doesn't exist)

### P1 -- High Impact Gaps
3. Document Rust native modules (new SUBSYSTEM_NATIVE.md)
4. Document Call/SideEffectStatement + CallExpr split in SUBSYSTEM_AIL.md
5. Expand sim_options.py coverage (mode presets, option categories)
6. Add CLI reference (`__main__.py` commands and flags)

### P2 -- Medium Impact
7. LLM integration guide (config, env vars, decompiler usage)
8. Enum type inference in SUBSYSTEM_RECOVERY.md
9. FunctionManager LMDB spilling architecture in SUBSYSTEM_KNOWLEDGE.md
10. AIL symbolic execution purpose in SUBSYSTEM_ENGINES.md
11. Add `semantic_naming/`, `notes/` to FILES.md

### P3 -- Low Impact / Nice to Have
12. SSAilification internals (PointerDisposition, Extract/Insert)
13. Protobuf schema details
14. corpus_tests/ mention in AGENTS.md
15. tablespecs.py usage explanation
16. Minor FILES.md additions (mips_gp_setting_simplifier, etc.)

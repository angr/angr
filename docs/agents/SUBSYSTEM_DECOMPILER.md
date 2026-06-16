# Decompiler Subsystem

All under `analyses/decompiler/`. Largest subsystem in angr.

## Pipeline (orchestrated by `Decompiler` in decompiler.py)
1. `Clinic` (clinic.py) — VEX→AIL, stack tracking, callsites, SSA, variable recovery, type inference
2. Graph simplification — BEFORE_REGION_IDENTIFICATION passes on AIL graph
3. `RegionIdentifier` (region_identifier.py) — identify loops, if-else, switch regions
4. Region simplification — DURING_REGION_IDENTIFICATION passes; may re-run RegionIdentifier
5. `RecursiveStructurer` → Phoenix/Dream/SAILR — convert region graph to SequenceNode tree
6. `RegionSimplifier` (region_simplifiers/) — goto elimination, if-merging, etc.
7. Post-structuring passes — AFTER_STRUCTURING optimization passes
8. Dephication (dephication/) — SSA → normal variables
9. `CStructuredCodeGenerator` (structured_codegen/c.py) — emit C source

Entry: `proj.analyses.Decompiler(func)` → `.codegen.text`

## Clinic Stages
INITIALIZATION → AIL_GRAPH_CONVERSION → MAKE_RETURN_SITES → MAKE_ARGUMENT_LIST → TRACK_STACK_POINTERS → CONSTANT_PROPAGATION → MAKE_CALLSITES → POST_CALLSITES → PRE_SSA_LEVEL0_FIXUPS → SSA_LEVEL0_TRANSFORMATION → PRE_SSA_LEVEL1_SIMPLIFICATIONS → SSA_LEVEL1_TRANSFORMATION → POST_SSA_LEVEL1_SIMPLIFICATIONS → RECOVER_VARIABLES → SEMANTIC_VARIABLE_NAMING → COLLECT_EXTERNS

Supports `start_stage`/`end_stage`/`skip_stages` for partial execution.

## SSAilification (`ssailification/`)
- Converts AIL graph to partial-SSA using VirtualVariable nodes
- Two sub-passes: TraversalAnalysis (build def-use), RewritingAnalysis (insert phi, rename)
- Clinic runs SSA at two levels: level-0 (before simplification) and level-1 (after)
- Stack variable identification via `PointerDisposition` — tracks how pointers are used (loaded, stored, passed) to distinguish stack variables from pointer arithmetic
- Uses `Extract`/`Insert` AIL expressions for sub-register and partial-variable access patterns

## Optimization Pass System
- Base classes: `BaseOptimizationPass` (abstract with `_check()`/`_analyze()`), `OptimizationPass` (graph-level), `SequenceOptimizationPass` (post-structuring on SequenceNode), `StructuringOptimizationPass` (requires RecursiveStructurer)
- Filtered by ARCHES, PLATFORMS, STAGE, STRUCTURING
- Stages: AFTER_AIL_GRAPH_CREATION (0) through AFTER_STRUCTURING (11) — 12 stages total
- Presets (presets/): basic, fast, full (default), malware

**Full reference for all passes, peepholes, region simplifiers, and rewriters: [SUBSYSTEM_DECOMPILER_SIMPLIFIERS.md](SUBSYSTEM_DECOMPILER_SIMPLIFIERS.md)**

Key pass categories (44 passes + 62 peephole rewrites):
- **Compiler artifacts**: StackCanarySimplifier, WinStackCanarySimplifier, RegisterSaveAreaSimplifier(Adv), BasePtrSaveSimplifier, RetAddrSaveSimplifier
- **Pattern recovery**: DivSimplifier, ModSimplifier, LoweredSwitchSimplifier
- **Deoptimization**: DuplicationReverter, CrossJumpReverter, ReturnDuplicator(Low/High), ReturnDeduplicator
- **String/intrinsic**: EagerStdStringConcatenation, EagerStdStringEval, InlinedStrlenSimplifier
- **Arch-specific**: MipsGpSettingSimplifier, X86GccGetPcSimplifier
- **Peephole**: PeepholeSimplifier drives 62 small rewrites (arithmetic, bitwise, boolean, conversion, memory, intrinsic recovery)

## Structuring (`structuring/`)
- **SAILR** (sailr.py) — **default structurer**; extends Phoenix with recursive structuring + deoptimization (USENIX 2024)
- **Phoenix** (phoenix.py) — schema-based; matches if-else, loops, switch. `_recursive` param controls behavior
- **Dream** (dream.py) — alternative structurer
- `STRUCTURER_CLASSES` dict maps names → classes; all produce: SequenceNode, ConditionNode, LoopNode, SwitchCaseNode, ConditionalBreakNode

## Region Simplifiers (`region_simplifiers/`)
Post-structuring simplifications (11 files). Goto elimination, conditional merging, loop normalization, expression folding, switch recovery. [Full listing](SUBSYSTEM_DECOMPILER_SIMPLIFIERS.md#region-simplifiers-region_simplifiers)

## CCall / Dirty Rewriters
- ccall_rewriters/ — convert VEX CC_OP helper calls to readable C. Per-arch: amd64, x86, arm. [Full listing](SUBSYSTEM_DECOMPILER_SIMPLIFIERS.md#ccall-rewriters-ccall_rewriters)
- dirty_rewriters/ — convert VEX dirty helpers (CPUID, RDTSC, etc.). amd64_dirty.py. [Full listing](SUBSYSTEM_DECOMPILER_SIMPLIFIERS.md#dirty-rewriters-dirty_rewriters)

## Code Generation (`structured_codegen/`)
- CStructuredCodeGenerator (c.py) — walks SequenceNode tree, emits C text
- dwarf_import.py — import DWARF debug info

## Semantic Naming (`semantic_naming/`)
- NamingOrchestrator applies renamers with two bases: `ClinicNamingBase` (pre-structuring: array_index, boolean, call_result, pointer, size) and `RegionNamingBase` (post-structuring: region_loop_counter)

## Key Data Flow
- AIL: typed statement-based IR (in ailment/)
- VirtualVariable: SSA variable throughout pipeline
- SimVariable: post-SSA variable (stack, register, memory)
- Graph: networkx.DiGraph of ailment.Block → becomes SequenceNode tree after structuring

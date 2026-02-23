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

## Optimization Pass System
- Base classes: `BaseOptimizationPass` (abstract with `_check()`/`_analyze()`), `OptimizationPass` (graph-level), `SequenceOptimizationPass` (post-structuring on SequenceNode), `StructuringOptimizationPass` (requires RecursiveStructurer)
- Filtered by ARCHES, PLATFORMS, STAGE, STRUCTURING
- Stages: AFTER_AIL_GRAPH_CREATION (0), BEFORE_SSA_LEVEL0 (1), AFTER_SINGLE_BLOCK_SIMPLIFICATION (2), BEFORE_SSA_LEVEL1 (3), AFTER_SSA_LEVEL1 (4), AFTER_MAKING_CALLSITES (5), AFTER_GLOBAL_SIMPLIFICATION (6), BEFORE_VARIABLE_RECOVERY (7), AFTER_VARIABLE_RECOVERY (8), BEFORE_REGION_IDENTIFICATION (9), DURING_REGION_IDENTIFICATION (10), AFTER_STRUCTURING (11)
- Presets (presets/): basic, fast, full (default), malware — `DecompilationPreset.get_optimization_passes(arch, platform)` filters by metadata

Key passes by category:
- **Compiler artifacts**: StackCanarySimplifier, RegisterSaveAreaSimplifier, BasePtrSaveSimplifier, RetAddrSaveSimplifier
- **Pattern recovery**: DivSimplifier, ModSimplifier, LoweredSwitchSimplifier, OverflowBuiltinSimplifier
- **Deoptimization**: DuplicationReverter, CrossJumpReverter, ReturnDuplicator*
- **Peephole**: PeepholeSimplifier drives ~60 small rewrites in peephole_optimizations/

## Structuring (`structuring/`)
- **SAILR** (sailr.py) — **default structurer**; extends Phoenix with recursive structuring + deoptimization (USENIX 2024)
- **Phoenix** (phoenix.py) — schema-based; matches if-else, loops, switch. `_recursive` param controls behavior
- **Dream** (dream.py) — alternative structurer
- `STRUCTURER_CLASSES` dict maps names → classes; all produce: SequenceNode, ConditionNode, LoopNode, SwitchCaseNode, ConditionalBreakNode

## Region Simplifiers (`region_simplifiers/`)
- goto.py — goto elimination
- cascading_ifs.py / if_.py / ifelse.py — merge/simplify conditionals
- loop.py — loop simplification (while/do-while/for)
- expr_folding.py — fold expressions across statements
- switch_cluster_simplifier.py / switch_expr_simplifier.py — switch cleanup

## CCall / Dirty Rewriters
- ccall_rewriters/ — convert VEX CC_OP helper calls to readable C. Per-arch: amd64, x86, arm
- dirty_rewriters/ — convert VEX dirty helpers. amd64_dirty.py

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

# Data Flow Analyses

## Reaching Definitions (`analyses/reaching_definitions/`)

Workhorse data-flow analysis. Tracks which definitions reach each program point.

- reaching_definitions.py — `ReachingDefinitionsAnalysis(ForwardAnalysis)`: main entry
- rd_state.py — `ReachingDefinitionsState`: wraps LiveDefinitions (defs, uses per register/mem/tmp)
- rd_initializer.py — `RDAStateInitializer`: sets up initial state (args, SP, etc.)
- dep_graph.py — `DepGraph`: directed graph of Definition nodes from RDA
- subject.py — `Subject`: what to analyze (function, block, or CFG node)
- engine_vex.py — `SimEngineRDVEX`: VEX IR engine (pre-decompilation)
- engine_ail.py — `SimEngineRDAIL`: AIL engine (decompiler pipeline)
- function_handler.py — `FunctionHandler`: handles call effects; `FunctionCallData` bundles call info
- function_handler_library/ — per-lib summaries: stdio.py, stdlib.py, string.py, unistd.py
- call_trace.py — call trace for inter-procedural analysis
- heap_allocator.py — heap allocation modeling
- external_codeloc.py — ExternalCodeLocation handling

Results stored in KB via `kb.defs` (ReachingDefinitionsModel):
- `model.observed_results` — LiveDefinitions at observation points
- `model.all_definitions` / `model.all_uses` — global def/use sets
- `analysis.dep_graph` — DepGraph (networkx DiGraph of Definitions)

## Propagator (`analyses/propagator/`)

Constant/expression propagation. VEX only; AIL uses SPropagator.

- propagator.py — `PropagatorAnalysis(ForwardAnalysis)`: `flavor` = "function" or "block"
- engine_base.py — base engine
- engine_vex.py — `SimEnginePropagatorVEX`
- top_checker_mixin.py — TOP value checking
- values.py — propagation value types
- vex_vars.py — VEX variable representations

Results: PropagationModel in `kb.propagations`

## Simplified/SSA Variants (decompiler-internal)
- s_propagator.py — `SPropagatorAnalysis`: AIL propagator on partial-SSA
- s_liveness.py — `SLivenessAnalysis`: LiveIn/LiveOut per block on partial-SSA
- s_reaching_definitions/ — `SReachingDefinitionsAnalysis` + SRDAModel + view

## Legacy / Other
- ddg.py — `DDG`: data dependency graph (simulation-based)
- vfg.py — `VFG`: value-flow graph (value-set analysis, uses SimState)
- vsa_ddg.py — VSA-based DDG
- cdg.py — `CDG`: control dependency graph
- data_dep/ — `DataDependencyAnalysis`: SimAction-based dependency

## Forward Analysis Framework (`analyses/forward_analysis/`)

Base for all iterative data-flow analyses. Worklist-based fixed-point computation.

- forward_analysis.py — `ForwardAnalysis[State, Node]`: merging, widening, graph visitor
- job_info.py — job tracking
- visitors/: graph.py (generic), function_graph.py (function CFG), call_graph.py (inter-proc), loop.py (loop-aware), single_node_graph.py

## Key Relationships
- ForwardAnalysis ← base for RDA, Propagator, VFG
- RDA is the primary data-flow analysis used throughout angr
- Decompiler runs RDA with AIL engine, then SPropagator/SLiveness on SSA form
- Propagator runs before decompilation to simplify VEX

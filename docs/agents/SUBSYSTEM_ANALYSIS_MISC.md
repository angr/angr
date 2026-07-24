# Miscellaneous Analyses

## Analysis Framework (`analyses/analysis.py`)
- `Analysis` — base class; subclass and call `register_analysis(Cls, "Name")`
- `AnalysesHub` — plugin vendor; accessed via `project.analyses.Name()`
- `AnalysesHubWithDefault` — adds type hints for built-in analyses

## Loop Analysis
- loopfinder.py — `LoopFinder`: find natural loops in CFG; produces Loop objects
- loop_analysis/loop_analysis.py — `LoopAnalysis`: characterize loops from decompiled AST
- loop_unroller/loop_unroller.py — `LoopUnroller`: unroll loops in AIL graphs

## Slicing
- backward_slice.py — `BackwardSlice`: backward slice on CFG+CDG+DDG (currently broken)
- slicer.py — `SimSlicer`: lightweight intra-IRSB slicer over VEX
- blade.py — `Blade`: inter-block slicer on networkx CFG DiGraph

## Code Analysis
- code_tagging.py — `CodeTagging`: tag functions (HAS_XOR, HAS_BITSHIFTS, HAS_SQL, LARGE_SWITCH)
- dominance_frontier.py — `DominanceFrontier`: compute from CFG
- proximity_graph.py — `ProximityGraphAnalysis`: function proximity (strings, calls, xrefs)
- xrefs.py — `XRefsAnalysis`: cross-references via lightweight VEX engine
- disassembly.py — `Disassembly`: structured disassembly output
- stack_pointer_tracker.py — `StackPointerTracker`: track SP delta through function
- static_hooker.py — `StaticHooker`: auto-hook library functions in static binaries
- init_finder.py — `InitializationFinder`: find init/fini routines (.init_array, _start chain)
- patchfinder.py — `PatchFinderAnalysis`: find patchable locations
- pathfinder.py — `Pathfinder`: find execution paths between points
- congruency_check.py — `CongruencyCheck`: check execution equivalence (VEX vs unicorn)
- reassembler.py — `Reassembler`: reassemble modified binary
- binary_optimizer.py — `BinaryOptimizer`: optimize binary via reassembly
- smc.py — `SelfModifyingCodeAnalysis`: detect self-modifying code

## Object-Oriented Analysis
- vtable.py — `VtableFinder`: detect C++ vtables
- class_identifier.py — `ClassIdentifier`: identify C++ classes
- find_objects_static.py — `StaticObjectFinder`: find objects in data sections

## Deobfuscation (`deobfuscator/`)
- api_obf_finder.py — find hash-based API import obfuscation
- api_obf_type2_finder.py — type-2 variant
- api_obf_peephole_optimizer.py — API deobfuscation peephole opts
- hash_lookup_api_deobfuscator.py — resolve hash-based API imports
- string_obf_finder.py — find string obfuscation
- string_obf_opt_passes.py / string_obf_peephole_optimizer.py — string deobf passes
- data_transformation_embedder.py — embed data transformations

## Unpacker (`unpacker/`)
- packing_detector.py — `PackingDetector`: entropy-based packed binary detection

## Purity (`purity/`)
- analysis.py — `AILPurityAnalysis`: determine if functions are pure (no side effects)

## Other
- veritesting.py — `Veritesting`: path merging during symbolic execution
- callee_cleanup_finder.py — find callee-cleanup calling conventions
- codecave.py — `CodeCaveAnalysis`: find code caves (alignment gaps, unreachable code)
- outliner/outliner.py — `Outliner`: extract repeated code patterns
- fcp/fcp.py — `FastConstantPropagation`
- soot_class_hierarchy.py — `SootClassHierarchy`: Java class hierarchy

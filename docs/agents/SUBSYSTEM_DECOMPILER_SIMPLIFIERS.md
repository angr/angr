# Decompiler Simplifiers & Optimization Passes

Detailed reference for all decompiler simplification passes. Parent: [SUBSYSTEM_DECOMPILER.md](SUBSYSTEM_DECOMPILER.md).

All under `analyses/decompiler/`.

## Optimization Pass Infrastructure

Base classes in `optimization_passes/optimization_pass.py`:
- `BaseOptimizationPass` — abstract with `_check()`/`_analyze()`
- `OptimizationPass` — graph-level (operates on AIL DiGraph)
- `SequenceOptimizationPass` — post-structuring (operates on SequenceNode tree)
- `StructuringOptimizationPass` — requires RecursiveStructurer

Engine in `optimization_passes/engine_base.py`: `SimplifierAILState`/`SimplifierAILEngine` — drives peephole application.

### Stages (OptimizationPassStage enum)
0=AFTER_AIL_GRAPH_CREATION, 1=BEFORE_SSA_LEVEL0, 2=AFTER_SINGLE_BLOCK_SIMPLIFICATION, 3=BEFORE_SSA_LEVEL1, 4=AFTER_SSA_LEVEL1, 5=AFTER_MAKING_CALLSITES, 6=AFTER_GLOBAL_SIMPLIFICATION, 7=BEFORE_VARIABLE_RECOVERY, 8=AFTER_VARIABLE_RECOVERY, 9=BEFORE_REGION_IDENTIFICATION, 10=DURING_REGION_IDENTIFICATION, 11=AFTER_STRUCTURING

### Presets (`presets/`)
basic, fast, full (default), malware — `DecompilationPreset.get_optimization_passes(arch, platform)` filters by ARCHES/PLATFORMS/STAGE/STRUCTURING metadata.

---

## Optimization Passes (`optimization_passes/`)

### Stack & Register Artifact Removal
- `base_ptr_save_simplifier.py` → `BasePointerSaveSimplifier` — removes base pointer save/restore
- `register_save_area_simplifier.py` → `RegisterSaveAreaSimplifier` — removes callee-saved register spill/reload
- `register_save_area_simplifier_adv.py` → `RegisterSaveAreaSimplifierAdvanced` — advanced register save areas
- `ret_addr_save_simplifier.py` → `RetAddrSaveSimplifier` — removes return address storage
- `stack_canary_simplifier.py` → `StackCanarySimplifier` — removes stack canary checks (Linux)
- `win_stack_canary_simplifier.py` → `WinStackCanarySimplifier` — removes stack canary checks (Windows PE)

### Division & Modulo Recovery
- `div_simplifier.py` → `DivSimplifier` — recovers division from multiply-shift compiler patterns
- `mod_simplifier.py` → `ModSimplifier` — recovers modulo from div-mul-sub patterns

### Control Flow Deoptimization
- `cross_jump_reverter.py` → `CrossJumpReverter` — reverts compiler cross-jumping (tail merging)
- `duplication_reverter/` → `DuplicationReverter` — reverts code duplication; sub-components: `ail_merge_graph.py` (AILBlockSplit/AILMergeGraph), `similarity.py` (longest_ail_graph_subseq), `errors.py`, `utils.py`
- `return_duplicator_base.py` → `ReturnDuplicatorBase` — base for return stmt duplication
- `return_duplicator_low.py` → `ReturnDuplicatorLow` — heavy return duplication (goto version)
- `return_duplicator_high.py` → `ReturnDuplicatorHigh` — light return duplication (goto-less)
- `ret_deduplicator.py` → `ReturnDeduplicator` — deduplicates identical return statements
- `switch_default_case_duplicator.py` → `SwitchDefaultCaseDuplicator` — duplicates default case for structuring
- `switch_reused_entry_rewriter.py` → `SwitchReusedEntryRewriter` — rewrites reused switch entry nodes
- `lowered_switch_simplifier.py` → `LoweredSwitchSimplifier` — recovers switch from if-chains

### Call & Statement Rewriting
- `call_stmt_rewriter.py` → `CallStatementRewriter` — rewrites Call statements to assignments
- `code_motion.py` → `CodeMotionOptimization` — hoists common statements out of branches
- `deadblock_remover.py` → `DeadblockRemover` — removes condition-unreachable blocks
- `tag_slicer.py` → `TagSlicer` — removes unmarked/unneeded statements

### Condition & Constant Handling
- `condition_constprop.py` → `ConditionConstantPropagation` — propagates constant conditions through branches
- `const_derefs.py` → `ConstDereferencePass` — substitutes constant memory dereferences
- `const_prop_reverter.py` → `ConstantPropagationReverter` — reverts overly-aggressive constant propagation
- `flip_boolean_cmp.py` → `FlipBooleanConditionPass` — normalizes boolean comparison direction

### Expression Rewriting
- `determine_load_sizes.py` → `DetermineLoadSizes` — infers sizes for Load expressions
- `expr_op_swapper.py` → `ExpressionOpSwapper` — canonicalizes operand order
- `ite_expr_converter.py` → `ITEExprConverter` — converts if-then-else blocks to ITE expressions
- `ite_region_converter.py` → `ITERegionConverter` — converts ITE-assignment regions to ternary expressions

### String & Intrinsic Recovery
- `eager_std_string_concatenation.py` → `EagerStdStringConcatenationPass` — merges std::string creation sequences
- `eager_std_string_eval.py` → `EagerStdStringEvaluation` — evaluates constant std::string calls
- `inlined_strlen_simplifier.py` → `InlinedStrlenSimplifier` — recovers strlen() from inlined loop
- `inlined_string_transformation_simplifier.py` — recovers string transformation intrinsics
- `static_vvar_rewriter.py` → `StaticVVarRewriter` — rewrites static virtual variables (FixedBuffer/FixedBufferPtr)

### Architecture-Specific
- `mips_gp_setting_simplifier.py` → `MipsGpSettingSimplifier` — removes $gp-setting stmts (MIPS)
- `x86_gcc_getpc_simplifier.py` → `X86GccGetPcSimplifier` — removes `__x86.get_pc_thunk` calls

### Peephole Integration
- `peephole_simplifier.py` → `PostStructuringPeepholeOptimizationPass` — runs peephole rewrites post-structuring (separate from pre-structuring PeepholeSimplifier)

---

## Peephole Optimizations (`peephole_optimizations/`)

Base: `base.py` (`PeepholeOptimizationStmtBase`/`PeepholeOptimizationExprBase`), `utils.py`.

Driven by the PeepholeSimplifier pass. Each file implements a single small rewrite pattern.

### Arithmetic & Division
- `a_div_const_add_a_mul_n_div_const.py` → `ADivConstAddAMulNDivConst` — `a/N0 + (a*N1)/N0` simplification
- `a_mul_const_div_shr_const.py` → `AMulConstDivShrConst` — `(A*N0/N1) >> N2` simplification
- `a_mul_const_sub_a.py` → `AMulConstSubA` — `a*N - a` → `a*(N-1)`
- `a_shl_const_sub_a.py` → `AShlConstSubA` — `(a<<N) - a` → `a*(2^N - 1)`
- `a_sub_a_div.py` → `ASubADiv` — `a - a/N` → `a*(N-1)/N`
- `a_sub_a_shr_const_shr_const.py` → `ASubAShrConstShrConst` — cdq/sub/sar signed-div pattern
- `a_sub_a_sub_n.py` → `ASubASubN` — `expr - (expr - N)` → `N`
- `modulo_simplifier.py` → `ModuloSimplifier` — `a - (a/N)*N` → `a % N`
- `optimized_div_simplifier.py` → `OptimizedDivisionSimplifier` — right-shift-based division recovery
- `sar_to_signed_div.py` → `SarToSignedDiv` — arithmetic shift → signed division

### Bitwise & Shift
- `bswap.py` → `Bswap` — byte-swap pattern recognition (16-bit, 32-bit)
- `coalesce_adjacent_shrs.py` → `CoalesceAdjacentShiftRights` — merges adjacent SHR/SAR
- `conv_shl_shr.py` → `ConvShlShr` — `(expr << P) >> Q` simplification
- `extended_byte_and_mask.py` → `ExtendedByteAndMask` — extended byte & mask simplification
- `remove_redundant_bitmasks.py` → `RemoveRedundantBitmasks` — removes no-op AND masks
- `remove_redundant_shifts.py` → `RemoveRedundantShifts` — removes no-op shifts
- `remove_redundant_shifts_around_comparators.py` → `RemoveRedundantShiftsAroundComparators`
- `rewrite_bit_extractions.py` → `RewriteBitExtractions` — normalizes bit extraction patterns
- `rol_ror.py` → `RolRorRewriter` — recognizes rotate-left/rotate-right patterns
- `shl_to_mul.py` → `ShlToMul` — `a << N` → `a * 2^N`

### Type Conversions
- `conv_a_sub0_shr_and.py` → `ConvASub0ShrAnd` — `Conv(M->1, (expr >> N) & 1)` simplification
- `evaluate_const_conversions.py` → `EvaluateConstConversions` — constant-folds conversions
- `eager_eval.py` → `EagerEvaluation` — eagerly evaluates constant expressions
- `remove_cascading_conversions.py` → `RemoveCascadingConversions` — merges adjacent casts
- `remove_noop_conversions.py` → `RemoveNoopConversions` — removes identity conversions
- `remove_redundant_conversions.py` → `RemoveRedundantConversions` — removes/rewrites unnecessary conversions
- `remove_redundant_reinterprets.py` → `RemoveRedundantReinterprets` — simplifies nested Reinterpret

### Boolean & Conditional
- `bitwise_or_to_logical_or.py` → `BitwiseOrToLogicalOr` — `(a|b) == 0` to logical form
- `bool_expr_xor_1.py` → `BoolExprXor1` — `bool_expr ^ 1` → `!bool_expr`
- `cmpord_rewriter.py` → `CmpORDRewriter` — CmpORD → common comparisons
- `coalesce_same_cascading_ifs.py` → `CoalesceSameCascadingIfs` — merges identical cascading ifs
- `invert_negated_logical_conjuction_disjunction.py` → `InvertNegatedLogicalConjunctionsAndDisjunctions` — De Morgan push-in
- `one_sub_bool.py` → `OneSubBool` — `1 - bool_expr` → `!bool_expr`
- `remove_empty_if_body.py` → `RemoveEmptyIfBody` — removes empty If bodies
- `remove_redundant_ite_branch.py` → `RemoveRedundantITEBranches`
- `remove_redundant_ite_comparisons.py` → `RemoveRedundantITEComparisons`
- `remove_redundant_nots.py` → `RemoveRedundantNots` — `Not(Not(x))` → `x`
- `single_bit_cond_to_boolexpr.py` → `SingleBitCondToBoolExpr`
- `single_bit_xor.py` → `SingleBitXor` — single-bit XOR simplification

### Memory & Pointer
- `basepointeroffset_add_n.py` → `BasePointerOffsetAddN` — `(Ptr - M) + N` simplification
- `basepointeroffset_and_mask.py` → `BasePointerOffsetAndMask` — `Ptr & mask` simplification
- `constant_derefs.py` → `ConstantDereferences` — dereferences loads from read-only memory
- `remove_const_insert.py` → `RemoveConstInsert` — `Insert(c0, c1, v)` simplification
- `remove_redundant_derefs.py` → `RemoveRedundantDerefs` — `*(&v)` → `v`
- `tidy_stack_addr.py` → `TidyStackAddr` — consolidates StackBaseOffset arithmetic

### Concat & Extraction
- `concat_simplifier.py` → `ConcatSimplifier` — simplifies Concat expressions

### Intrinsic & Library Recovery
- `cas_intrinsics.py` → `CASIntrinsics` — lock-prefixed → CAS intrinsic calls
- `inlined_memcpy.py` → `InlinedMemcpy` — inlined copy → memcpy()
- `inlined_memset.py` → `InlinedMemset` — inlined fill → memset()
- `inlined_strcpy.py` → `InlinedStrcpy` — inlined string copy → strcpy()
- `inlined_strcpy_consolidation.py` → `InlinedStrcpyConsolidation` — merges multiple strcpy
- `inlined_wcscpy.py` → `InlinedWcscpy` — inlined wide copy → wcscpy()
- `inlined_wcscpy_consolidation.py` → `InlinedWcscpyConsolidation` — merges multiple wcscpy
- `remove_cxx_destructor_calls.py` → `RemoveCxxDestructorCalls`
- `rewrite_conv_mul.py` → `RewriteConvMul` — moves multiplication inside conversion
- `rewrite_cxx_operator_calls.py` → `RewriteCxxOperatorCalls` — C++ operator calls → infix operators

### Architecture-Specific Peepholes
- `arm_cmpf.py` → `ARMCmpF` — ARM floating-point comparison rewrite
- `simplify_pc_relative_loads.py` → `SimplifyPcRelativeLoads`
- `rewrite_mips_gp_loads.py` → `RewriteMipsGpLoads` — MIPS $gp-based load rewrite

---

## Region Simplifiers (`region_simplifiers/`)

Post-structuring simplifications on the SequenceNode tree.

- `region_simplifier.py` → `RegionSimplifier` — orchestrator; iterates sub-simplifiers to fixpoint
- `goto.py` → `GotoSimplifier` — goto elimination (largest/most complex simplifier)
- `if_.py` → `IfSimplifier` — removes unnecessary jumps after If nodes
- `ifelse.py` → `IfElseFlattener` — removes unnecessary Else when If body returns/breaks
- `cascading_ifs.py` → `CascadingIfsRemover` — merges cascading If into If-ElseIf chains
- `cascading_cond_transformer.py` → `CascadingConditionTransformer` — transforms cascading if-else into combined conditions
- `loop.py` → `LoopSimplifier` — while/do-while/for loop normalization
- `expr_folding.py` → `ExpressionFolder` — folds single-use definitions into their use sites; includes `ExpressionCounter`, `StoreStatementFinder`, `InterferenceChecker`
- `switch_cluster_simplifier.py` → `SwitchClusterFinder` + `simplify_switch_clusters()` — recovers switch-case from If clusters
- `switch_expr_simplifier.py` → `SwitchExpressionSimplifier` — simplifies switch expression forms
- `node_address_finder.py` → `NodeAddressFinder` — collects node addresses (utility)

---

## CCall Rewriters (`ccall_rewriters/`)

Convert VEX CC_OP helper calls (condition codes, FP status) into readable C expressions.

- `rewriter_base.py` → `CCallRewriterBase` — base class; dispatches by `CC_OP` value
- `amd64_ccalls.py` → `AMD64CCallRewriter` — AMD64 condition code rewrites (amd64g_calculate_condition)
- `x86_ccalls.py` → `X86CCallRewriter` — x86 condition code rewrites (x86g_calculate_condition)
- `arm_ccalls.py` → `ARMCCallRewriter` — ARM condition code rewrites (armg_calculate_condition)

Pattern: VEX lifts flag-setting instructions into CC_OP/CC_DEP helper calls. Rewriters pattern-match the CC_OP constant and operands to emit `a < b`, `a == 0`, etc.

---

## Dirty Rewriters (`dirty_rewriters/`)

Convert VEX "dirty" helper calls (side-effecting operations) into readable C.

- `rewriter_base.py` → `DirtyRewriterBase` — base class
- `amd64_dirty.py` → `AMD64DirtyRewriter` — AMD64 dirty helpers (CPUID, RDTSC, XGETBV, etc.)

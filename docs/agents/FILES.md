# angr File Index

Every .py file in angr/ with terse description. Grouped by directory.

## Top-Level
__main__.py — CLI entry point: `angr decompile` and `angr disassemble` commands
project.py — Project: main entry, loads binary via CLE
factory.py — AngrObjectFactory: creates blocks, states, simgr
sim_state.py — SimState: symbolic execution state
sim_state_options.py — SimStateOptions set class
sim_options.py — simulation option constants (LAZY_SOLVES, etc.)
sim_manager.py — SimulationManager: manages state stashes, stepping
knowledge_base.py — KnowledgeBase: container for analysis results
block.py — Block: wrapper around lifted IR blocks
codenode.py — BlockNode, HookNode for CFG graph nodes
code_location.py — CodeLocation: identifies instruction positions
errors.py — all angr exception classes
sim_procedure.py — SimProcedure base: library function hooks
sim_type.py — SimType hierarchy (Int, Pointer, Struct, Enum, Fd, etc.)
sim_variable.py — SimVariable types (register, stack, memory)
calling_conventions.py — SimCC + all arch-specific calling conventions
callable.py — Callable: call function symbolically
ail_callable.py — AIL-based callable
emulator.py — simple emulator interface
serializable.py — Serializable base class
keyed_region.py — KeyedRegion: track variable locations by offset
annocfg.py — AnnotatedCFG for path constraints
blade.py — Blade: backward slicing on CFG
slicer.py — SimSlicer: symbolic slicing
state_hierarchy.py — tracks parent-child state relationships
vaults.py — Vaults: store/retrieve states by ID
tablespecs.py — StringTableSpec: builds argv/envp string tables in memory for state setup
graph_utils.py — graph utility functions
llm_client.py — LLMClient: LLM integration via LiteLLM (env: ANGR_LLM_MODEL, ANGR_LLM_API_KEY, ANGR_LLM_API_BASE)

## ailment/
expression.py — AIL expressions: Const, Register, Load, BinaryOp, UnaryOp, Convert, ITE, VirtualVariable, CallExpr (value-returning calls), Extract, Insert, etc.
statement.py — AIL statements: Assignment, Store, Jump, ConditionalJump, SideEffectStatement (side-effect-only calls), Return
block.py — AIL Block: list of statements
block_walker.py — AILBlockWalker: visitor pattern for AIL
manager.py — Manager: creates AIL objects with unique IDs
converter_vex.py — VEX IRSB → AIL Block converter
converter_pcode.py — P-Code → AIL Block converter
converter_common.py — shared converter utilities
tagged_object.py — TaggedObject: base with metadata tags
constant.py — constant handling
utils.py — AIL utilities

## analyses/
analysis.py — Analysis base class, AnalysesHub, registration
backward_slice.py — BackwardSlice on CFG/CDG/DDG
binary_optimizer.py — BinaryOptimizer
bindiff.py — BinDiff: compare two binaries
boyscout.py — BoyScout: heuristic arch/endian detection
callee_cleanup_finder.py — find callee-cleanup functions
cdg.py — Control Dependency Graph
class_identifier.py — C++ class identification
codecave.py — find code caves in binary
code_tagging.py — tag code regions with semantic info
complete_calling_conventions.py — batch CC recovery for all functions
congruency_check.py — check function equivalence
datagraph_meta.py — data graph metadata
ddg.py — Data Dependency Graph
disassembly.py — structured disassembly output
disassembly_utils.py — disassembly utilities
dominance_frontier.py — dominance frontier computation
find_objects_static.py — find data objects statically
init_finder.py — find initialization routines
loop_analysis.py — loop analysis (top-level)
loopfinder.py — LoopFinder: find natural loops
patchfinder.py — find patchable locations
pathfinder.py — find execution paths
proximity_graph.py — function proximity analysis
reassembler.py — reassemble modified binary
s_liveness.py — simplified liveness analysis
smc.py — self-modifying code detection
soot_class_hierarchy.py — Soot/Java class hierarchy
s_propagator.py — simplified propagator
stack_pointer_tracker.py — track SP changes through function
static_hooker.py — auto-hook library functions
veritesting.py — Veritesting analysis
vfg.py — Value-Flow Graph
vsa_ddg.py — VSA-based DDG
vtable.py — virtual table detection
xrefs.py — cross-reference analysis

## analyses/cfg/
cfg.py — CFG analysis registration entry points
cfg_base.py — CFGBase shared base class
cfg_fast.py — CFGFast: static disassembly-based CFG
cfg_emulated.py — CFGEmulated: symbolic execution-based CFG
cfg_fast_soot.py — CFGFast for Java/Soot
cfg_job_base.py — CFG work item base
cfg_arch_options.py — architecture-specific CFG options
cfb.py — CFBlanket: full binary coverage

## analyses/cfg/indirect_jump_resolvers/
resolver.py — IndirectJumpResolver base
default_resolvers.py — default resolver list per arch
jumptable.py — jump table (switch) resolver
const_resolver.py — constant value resolver
memload_resolver.py — memory load resolver
constant_value_manager.py — constant value tracking
propagator_utils.py — propagator integration utils
syscall_resolver.py — syscall resolver
Arch-specific: amd64_elf_got.py, amd64_pe_iat.py, x86_elf_pic_plt.py, x86_pe_iat.py, arm_elf_fast.py, mips_elf_fast.py, mips_elf_got.py, aarch64_macho_got.py

## analyses/cfg_slice_to_sink/
cfg_slice_to_sink.py — slice CFG from source to sink
graph.py — graph operations for slicing
transitions.py — transition handling

## analyses/calling_convention/
calling_convention.py — CallingConventionAnalysis
fact_collector.py — gather CC facts from RDA
utils.py — CC recovery utilities

## analyses/data_dep/
data_dependency_analysis.py — data dependency analysis
dep_nodes.py — dependency node types
sim_act_location.py — SimAction location tracking

## analyses/decompiler/
decompiler.py — Decompiler: orchestrates full pipeline
clinic.py — Clinic: VEX→AIL + initial simplification
decompilation_options.py — decompilation option definitions
decompilation_cache.py — decompiled function cache
ail_simplifier.py — AILSimplifier: RDA + propagation on AIL
block_simplifier.py — simplify individual AIL blocks
expression_narrower.py — narrow expression bit widths
ailgraph_walker.py — walk AIL function graphs
graph_region.py — GraphRegion for structuring
region_identifier.py — identify regions (loops, if-else, switch)
region_walker.py — walk region trees
sequence_walker.py — walk sequence nodes
block_io_finder.py — find block inputs/outputs
block_similarity.py — compare block similarity
condition_processor.py — process/simplify conditions
goto_manager.py — manage goto statements
callsite_maker.py — create callsite prototypes
return_maker.py — insert return statements
empty_node_remover.py — remove empty nodes
redundant_label_remover.py — remove unused labels
label_collector.py — collect labels
jump_target_collector.py — collect jump targets
jumptable_entry_condition_rewriter.py — rewrite jump table conditions
node_replacer.py — replace nodes in graphs
seq_to_blocks.py — convert sequences to blocks
stack_item.py — stack item representation
utils.py — decompiler utilities

## analyses/decompiler/structuring/
structurer_base.py — structurer base class
structurer_nodes.py — SequenceNode, ConditionNode, LoopNode, SwitchCaseNode
phoenix.py — Phoenix: primary structuring algorithm
dream.py — Dream: alternative structurer
recursive_structurer.py — RecursiveStructurer wrapper
sailr.py — SAILR: Rust-based structurer interface

## analyses/decompiler/region_simplifiers/
region_simplifier.py — region simplification orchestrator
cascading_ifs.py — merge cascading if-else chains
cascading_cond_transformer.py — transform cascading conditions
if_.py — if simplification
ifelse.py — if-else simplification
goto.py — goto elimination
loop.py — loop simplification
expr_folding.py — expression folding
switch_cluster_simplifier.py — simplify switch clusters
switch_expr_simplifier.py — simplify switch expressions
node_address_finder.py — find node addresses

## analyses/decompiler/optimization_passes/
optimization_pass.py — OptimizationPass base (STAGE_0–3)
engine_base.py — optimization engine base
stack_canary_simplifier.py — remove stack canary checks
win_stack_canary_simplifier.py — Windows stack canary removal
register_save_area_simplifier.py — remove callee-save spills
register_save_area_simplifier_adv.py — advanced register save removal
base_ptr_save_simplifier.py — remove base pointer save/restore
ret_addr_save_simplifier.py — remove return address saves
div_simplifier.py — simplify compiler division patterns
mod_simplifier.py — simplify compiler modulo patterns
lowered_switch_simplifier.py — recover switch from lowered form
cross_jump_reverter.py — revert cross-jumping
deadblock_remover.py — remove dead blocks
return_duplicator_base.py, return_duplicator_low.py, return_duplicator_high.py — return duplication for structuring
ret_deduplicator.py — deduplicate returns
code_motion.py — code motion optimization
const_derefs.py — resolve constant dereferences
const_prop_reverter.py — revert over-propagation
condition_constprop.py — const propagation through conditions
determine_load_sizes.py — determine correct load sizes
call_stmt_rewriter.py — rewrite call statements
expr_op_swapper.py — swap expression operand order
flip_boolean_cmp.py — flip boolean comparisons
ite_expr_converter.py, ite_region_converter.py — ITE conversion
peephole_simplifier.py — peephole optimization driver
static_vvar_rewriter.py — rewrite static virtual variables
tag_slicer.py — slice based on tags
switch_default_case_duplicator.py — duplicate switch default cases
switch_reused_entry_rewriter.py — rewrite reused switch entries
mips_gp_setting_simplifier.py — simplify MIPS GP register settings
eager_std_string_concatenation.py, eager_std_string_eval.py — C++ string optimization
inlined_string_transformation_simplifier.py, inlined_strlen_simplifier.py — inlined string recovery
x86_gcc_getpc_simplifier.py — x86 PIC get-PC simplification

### duplication_reverter/
duplication_reverter.py — revert compiler code duplication
ail_merge_graph.py — AIL merge graph for dedup
similarity.py — block similarity; errors.py — errors; utils.py — utilities

## analyses/decompiler/peephole_optimizations/
base.py — PeepholeOptimization base classes
utils.py — peephole utilities
Arithmetic: optimized_div_simplifier, sar_to_signed_div, shl_to_mul, modulo_simplifier, a_mul_const_div_shr_const, a_mul_const_sub_a, a_shl_const_sub_a, a_sub_a_div, a_sub_a_shr_const_shr_const, a_sub_a_sub_n, a_div_const_add_a_mul_n_div_const
Bit ops: bswap, rol_ror, concat_simplifier, rewrite_bit_extractions, coalesce_adjacent_shrs, single_bit_xor, extended_byte_and_mask, rewrite_conv_mul
Conversions: remove_noop_conversions, remove_cascading_conversions, evaluate_const_conversions, conv_shl_shr, conv_a_sub0_shr_and
Redundancy removal: remove_redundant_bitmasks, remove_redundant_shifts, remove_redundant_shifts_around_comparators, remove_redundant_nots, remove_redundant_conversions, remove_redundant_derefs, remove_redundant_reinterprets, remove_redundant_ite_branch, remove_redundant_ite_comparisons, remove_const_insert, remove_cxx_destructor_calls, remove_empty_if_body
Inlined functions: inlined_memcpy, inlined_memset, inlined_strcpy, inlined_strcpy_consolidation, inlined_wcscpy, inlined_wcscpy_consolidation
Comparisons: arm_cmpf, cmpord_rewriter, single_bit_cond_to_boolexpr
Boolean: bitwise_or_to_logical_or, bool_expr_xor_1, one_sub_bool, invert_negated_logical_conjuction_disjunction, coalesce_same_cascading_ifs
Other: basepointeroffset_add_n, basepointeroffset_and_mask, constant_derefs, eager_eval, cas_intrinsics, rewrite_cxx_operator_calls, rewrite_mips_gp_loads, simplify_pc_relative_loads, tidy_stack_addr

## analyses/decompiler/ccall_rewriters/
rewriter_base.py — CCall rewriter base class
amd64_ccalls.py — AMD64 condition code rewriting
x86_ccalls.py — x86 condition code rewriting
arm_ccalls.py — ARM condition code rewriting

## analyses/decompiler/dirty_rewriters/
rewriter_base.py — dirty rewriter base
amd64_dirty.py — AMD64 dirty helper rewriting

## analyses/decompiler/ssailification/
ssailification.py — convert AIL to SSA form
rewriting.py — SSA rewriting pass
rewriting_engine.py — SSA rewriting engine
rewriting_state.py — SSA rewriting state
traversal.py — graph traversal for SSA
traversal_engine.py — SSA traversal engine
traversal_state.py — SSA traversal state

## analyses/decompiler/dephication/
dephication_base.py — dephication (out-of-SSA) base
graph_dephication.py — graph-based dephication
seqnode_dephication.py — sequence node dephication
graph_rewriting.py — graph rewriting for dephication
graph_vvar_mapping.py — virtual variable mapping
rewriting_engine.py — dephication rewriting engine

## analyses/decompiler/structured_codegen/
base.py — BaseStructuredCodeGenerator
c.py — CStructuredCodeGenerator: emit C
dummy.py — dummy code generator
dwarf_import.py — import DWARF debug info

## analyses/decompiler/presets/
preset.py — DecompilationPreset base
basic.py, fast.py, full.py, malware.py — optimization presets

## analyses/decompiler/counters/
boolean_counter.py, call_counter.py, expression_counters.py, seq_cf_structure_counter.py — various AST counters

## analyses/decompiler/notes/
decompilation_note.py — decompilation note base
deobfuscated_strings.py — deobfuscated string notes

## analyses/decompiler/semantic_naming/
orchestrator.py — naming orchestrator
naming_base.py — naming rule base class
Rules: array_index_naming, boolean_naming, call_result_naming, pointer_naming, region_loop_counter_naming, size_naming

## analyses/deobfuscator/
api_obf_finder.py — find hash-based API obfuscation
api_obf_type2_finder.py — type 2 API obfuscation finder
api_obf_peephole_optimizer.py — API deobfuscation peephole opts
hash_lookup_api_deobfuscator.py — resolve hash-based API imports
string_obf_finder.py — find string obfuscation
string_obf_opt_passes.py — string deobfuscation opt passes
string_obf_peephole_optimizer.py — string deobfuscation peephole opts
data_transformation_embedder.py — embed data transformations
irsb_reg_collector.py — collect register uses from IRSBs
scope_ops_analyzer.py — analyze obfuscation scope ops

## analyses/flirt/
flirt.py — FlirtAnalysis: FLIRT signature matching
flirt_matcher.py — pattern matching engine
flirt_sig.py — signature file parsing
flirt_module.py — module within signature
flirt_node.py — trie node for matching
flirt_function.py — matched function info
flirt_utils.py — FLIRT utilities
consts.py — FLIRT constants

## analyses/forward_analysis/
forward_analysis.py — ForwardAnalysis: worklist fixed-point base
job_info.py — job tracking
visitors/: graph.py (generic), function_graph.py (function CFG), call_graph.py (inter-proc), loop.py (loop-aware), single_node_graph.py (single node)

## analyses/identifier/
identify.py — Identifier: identify library functions by behavior
runner.py — execute candidate functions symbolically
func.py — function representation for identification
custom_callable.py — custom callable for identification
errors.py — identifier errors
functions/: malloc, free, memcpy, memset, memcmp, strlen, strcmp, strcpy, strncmp, strncpy, strcasecmp, printf, sprintf, snprintf, fdprintf, atoi, based_atoi, strtol, int2str, recv_until, skip_calloc, skip_realloc, skip_recv_n

## analyses/loop_analysis/
loop_analysis.py — detailed loop characterization

## analyses/loop_unroller/
loop_unroller.py — unroll loops in AIL

## analyses/outliner/
outliner.py — extract repeated code patterns

## analyses/propagator/
propagator.py — PropagatorAnalysis: constant/expr propagation
engine_base.py — propagator engine base
engine_vex.py — VEX propagation engine
top_checker_mixin.py — TOP value checking
values.py — propagation value types
vex_vars.py — VEX variable representations

## analyses/purity/
analysis.py — PurityAnalysis: determine pure functions
engine.py — purity analysis engine

## analyses/reaching_definitions/
reaching_definitions.py — ReachingDefinitionsAnalysis
rd_state.py — RDA state (live defs, uses)
rd_initializer.py — initialize RDA state
dep_graph.py — dependency graph from RDA
call_trace.py — call trace for inter-proc analysis
subject.py — analysis subject (function, block)
external_codeloc.py — external code location
heap_allocator.py — heap allocation modeling
engine_vex.py — VEX engine for RDA
engine_ail.py — AIL engine for RDA
function_handler.py — call handling during RDA
function_handler_library/: stdio.py, stdlib.py, string.py, unistd.py — per-lib function effects

## analyses/s_reaching_definitions/
s_reaching_definitions.py — simplified RDA
s_rda_model.py — simplified RDA model
s_rda_view.py — RDA view

## analyses/typehoon/
typehoon.py — Typehoon: constraint-based type inference
typeconsts.py — type constants (Int8, Pointer, Struct, etc.)
typevars.py — type variables for constraint system
translator.py — TypeTranslator: bidirectional SimType ↔ TypeConstant conversion
simple_solver.py — solve type constraints
dfa.py — data flow for type inference
variance.py — type variance tracking

## analyses/unpacker/
packing_detector.py — detect packed binaries
obfuscation_detector.py — detect obfuscation

## analyses/variable_recovery/
variable_recovery.py — full variable recovery
variable_recovery_fast.py — fast intra-procedural variant
variable_recovery_base.py — shared base class
engine_base.py — recovery engine base
engine_vex.py — VEX recovery engine
engine_ail.py — AIL recovery engine
irsb_scanner.py — IRSB scanning for stack vars
annotations.py — variable annotations

## analyses/fcp/
fcp.py — FunctionContinuationPatch

## angrdb/
db.py — AngrDB: SQLAlchemy persistent storage
models.py — DB ORM models
serializers/: kb.py (KnowledgeBase), cfg_model.py (CFG), funcs.py (functions), variables.py, xrefs.py, comments.py, labels.py, loader.py, structured_code.py

## concretization_strategies/
base.py — SimConcretizationStrategy base
single.py — single value; any.py — any satisfying value; any_named.py — any named region
eval.py — evaluate N solutions; range.py — range of values; max.py — maximum value
norepeats.py — no repeated values; norepeats_range.py — no repeats in range
nonzero.py — non-zero; nonzero_range.py — non-zero in range; unlimited_range.py — unlimited range
solutions.py — fixed solution set; controlled_data.py — controlled data regions
signed_add.py — signed addition; logging.py — logging strategy

## distributed/
server.py — distributed analysis server
worker.py — distributed analysis worker

## engines/
engine.py — UberEngine: composes all engine types
successors.py — SimSuccessors: successor states
hook.py — HooksMixin: SimProcedure hooks
procedure.py — ProcedureMixin: execute SimProcedures
syscall.py — SyscallMixin: syscall dispatch
failure.py — SimEngineFailure: error handling
concrete.py — ConcreteEngine: GDB/avatar2
unicorn.py — SimEngineUnicorn: fast concrete execution
icicle.py — IcicleEngine: Rust-based concrete VM with breakpoints, tracing, edge coverage

## engines/vex/
lifter.py — VEX lifting
claripy/irop.py — VEX IR operation implementations
claripy/ccall.py — VEX helper functions (condition codes)
claripy/datalayer.py — VEX data layer
heavy/heavy.py — HeavyVEXMixin: full symbolic engine
heavy/actions.py — SimAction tracking
heavy/dirty.py — dirty helper calls
heavy/inspect.py — breakpoint inspection
heavy/resilience.py — error recovery
heavy/concretizers.py — value concretization
heavy/super_fastpath.py — super fast path optimization
light/light.py — light VEX engine (no state)
light/resilience.py — light engine error recovery
light/slicing.py — slicing support

## engines/light/
engine.py — light engine base (abstract interpretation)
data.py — light engine data types

## engines/ail/
engine_light.py — AIL light engine
engine_successors.py — AIL successor generation
callstack.py — call stack tracking
setup.py — AIL engine setup

## engines/pcode/
engine.py — P-Code execution engine
lifter.py — P-Code lifting
behavior.py — P-Code operation behaviors
emulate.py — P-Code emulation
cc.py — P-Code calling conventions

## engines/soot/
engine.py — Soot execution engine
field_dispatcher.py — Java field dispatch
method_dispatcher.py — Java method dispatch
exceptions.py — Soot exceptions
expressions/: arrayref, base, binop, cast, condition, constants, instancefieldref, instanceOf, invoke, length, local, new, newArray, newMultiArray, paramref, phi, staticfieldref, thisref, unsupported
statements/: assign, base, goto, identity, if_, invoke, return_, switch, throw
values/: arrayref, base, constants, instancefieldref, local, paramref, staticfieldref, strref, thisref

## exploration_techniques/
base.py — ExplorationTechnique base class
common.py — common utilities
explorer.py — Explorer: find/avoid addresses
dfs.py — DFS: depth-first search
lengthlimiter.py — max path length
loop_seer.py — LoopSeer: detect/bound loops
local_loop_seer.py — function-local loop detection
veritesting.py — Veritesting: path merging
tracer.py — Tracer: follow concrete trace
driller_core.py — DrillerCore: hybrid fuzzing
director.py — Director: directed symex
spiller.py — Spiller: spill states to disk
spiller_db.py — SpillerDB: DB-backed spilling
threading.py — Threading: parallel stepping
stochastic.py — Stochastic: random selection
manual_mergepoint.py — explicit state merging
oppologist.py — Oppologist: concrete fallback
slicecutor.py — Slicecutor: execute along slice
bucketizer.py — group states by criteria
memory_watcher.py — discard states if memory high
timeout.py — stop after time limit
unique.py — avoid duplicate states
suggestions.py — user-guided exploration
stub_stasher.py — stash states at stubs
tech_builder.py — programmatic technique builder

## flirt/
build_sig.py — build FLIRT signatures from libraries

## knowledge_plugins/
plugin.py — KnowledgeBasePlugin base class
callsite_prototypes.py — per-callsite function prototypes
comments.py — address → comment mapping
custom_strings.py — user-defined string overrides
data.py — discovered data items
debug_variables.py — DWARF variable info
indirect_jumps.py — resolved indirect jumps
labels.py — address → label mapping
obfuscations.py — detected obfuscation info
patches.py — binary patches
structured_code.py — decompiled code cache
types.py — recovered type information

## knowledge_plugins/cfg/
cfg_manager.py — CFGManager: holds CFG models
cfg_model.py — CFGModel: CFG graph + metadata
cfg_node.py — CFGNode
memory_data.py — data references from CFG
indirect_jump.py — IndirectJump tracking

## knowledge_plugins/functions/
function_manager.py — FunctionManager: kb.functions[addr]
function.py — Function: name, addr, graph, blocks, CC, prototype
function_parser.py — parse function from CFG data
soot_function.py — Soot/Java function variant

## knowledge_plugins/key_definitions/
key_definition_manager.py — KeyDefinitionManager
definition.py — Definition: value at code location
atoms.py — Atom: register, memory, tmp locations
live_definitions.py — LiveDefinitions: current def-use state
rd_model.py — ReachingDefinitionsModel
uses.py — uses tracking
liveness.py — liveness analysis results
tag.py — definition tags
environment.py — environment definitions
heap_address.py — heap address tracking
constants.py — definition constants
undefined.py — undefined value sentinel
unknown_size.py — unknown size sentinel

## knowledge_plugins/propagations/
propagation_manager.py — PropagationManager
propagation_model.py — PropagationModel
prop_value.py — PropValue
states.py — propagation states

## knowledge_plugins/variables/
variable_manager.py — VariableManager: per-function variable info
variable_access.py — variable access tracking

## knowledge_plugins/xrefs/
xref_manager.py — XRefManager: cross-references
xref.py — XRef object
xref_types.py — XRef type enum

## knowledge_plugins/rtdb/
rtdb.py — RuntimeDb: LMDB-backed persistent store for FunctionManager spilling

## misc/
plugins.py — PluginHub/PluginPreset: generic plugin system
hookset.py — HookSet: ordered hook collection
autoimport.py — auto-import submodules
loggers.py — logging configuration
ansi.py — ANSI color codes
bug_report.py — bug report generation
picklable_lock.py — picklable threading lock
testing.py — test helpers
telemetry.py — telemetry
ux.py — UX helpers (deprecation warnings)

## procedures/
procedure_dict.py — ProcedureDict: lazy procedure registry
definitions/: cgc, gnulib, libstdcpp, linux_kernel, linux_loader, macho_libsystem, msvcr, parse_glibc, parse_syscalls_from_local_system, parse_win32json, types_stl
libc/: abort, access, atoi, atol, calloc, closelog, err, error, exit, fclose, feof, fflush, fgetc, fgets, fopen, fprintf, fputc, fputs, fread, free, fscanf, fseek, ftell, fwrite, getchar, getdelim, getegid, geteuid, getgid, gets, getuid, malloc, memcmp, memcpy, memset, openlog, perror, printf, putchar, puts, rand, realloc, rewind, scanf, setbuf, setvbuf, snprintf, sprintf, srand, sscanf, stpcpy, strcat, strchr, strcmp, strcpy, strlen, strncat, strncmp, strncpy, strnlen, strstr, strtol, strtoul, system, time, tmpnam, tolower, toupper, ungetc, vsnprintf, wchar
posix/: accept, bind, bzero, chroot, close, closedir, dup, fcntl, fdopen, fileno, fork, getenv, gethostbyname, getpass, getsockopt, htonl, htons, inet_ntoa, listen, mmap, open, opendir, poll, pread64, pthread, pwrite64, read, readdir, recv, recvfrom, select, send, setsockopt, sigaction, sim_time, sleep, socket, strcasecmp, strdup, strtok_r, syslog, tz, unlink, usleep, write
glibc/: __ctype_b_loc, __ctype_tolower_loc, __ctype_toupper_loc, dynamic_loading, __errno_location, __libc_init, __libc_start_main, scanf, sscanf
linux_kernel/: access, arch_prctl, arm_user_helpers, brk, cwd, fstat, fstat64, futex, getegid, geteuid, getgid, getpid, getrlimit, gettid, getuid, iovec, lseek, mmap, mprotect, munmap, openat, set_tid_address, sigaction, sigprocmask, stat, sysinfo, tgkill, time, uid, uname, unlink, vsyscall
linux_loader/: _dl_initial_error_catch_tsd, _dl_rtld_lock, sim_loader, tls
cgc/: allocate, deallocate, fdwait, random, receive, _terminate, transmit
win32/: critical_section, dynamic_loading, EncodePointer, ExitProcess, file_handles, GetCommandLine, GetCurrentProcessId, GetCurrentThreadId, gethostbyname, GetLastInputInfo, GetModuleHandle, GetProcessAffinityMask, heap, InterlockedExchange, is_bad_ptr, IsProcessorFeaturePresent, local_storage, mutex, sim_time, system_paths, VirtualAlloc, VirtualProtect
win32_kernel/: ExAllocatePool, ExFreePoolWithTag, __fastfail
win_user32/: chars, keyboard, messagebox
ntdll/: exceptions
msvcr/: fmode, __getmainargs, _initterm
advapi32/: (stubs)
libstdcpp/: std__terminate, std____throw_bad_alloc, std____throw_bad_cast, std____throw_length_error, std____throw_logic_error, _unwind_resume
gnulib/: xalloc_die, xstrtol_fatal
uclibc/: __uClibc_main
java/: unconstrained
java_lang/: character, double, exit, getsimplename, integer, load_library, math, string, stringbuilder, system
java_io/: read, write
java_jni/: array_operations, class_and_interface_operations, field_access, global_and_local_refs, method_calls, not_implemented, object_operations, string_operations, version_information
java_util/: collection, iterator, list, map, random, scanner_nextline
stubs/: b64_decode, caller, CallReturn, crazy_scanf, format_parser, Nop, NoReturnUnconstrained, PathTerminator, Redirect, ReturnChar, ReturnUnconstrained, syscall_stub, UnresolvableCallTarget, UnresolvableJumpTarget, UserHook
tracer/: random, receive, transmit
testing/: manyargs, retreg

## rustylib/ (Rust native module stubs)
automaton.pyi — EpsilonNFA, DeterministicFiniteAutomaton, State, Symbol for pattern matching
fuzzer.pyi — Fuzzer, InMemoryCorpus, OnDiskCorpus, ClientStats for LibAFL-based fuzzing
icicle.pyi — Icicle concrete VM: CPU state, memory, breakpoints, coverage, VmExit/ExceptionCode

## protos/
cfg_pb2.py, function_pb2.py, primitives_pb2.py, variables_pb2.py, xrefs_pb2.py — protobuf definitions

## simos/
simos.py — SimOS base class
userland.py — SimUserland: userspace base
linux.py — SimLinux: Linux process model
windows.py — SimWindows: Windows process model
cgc.py — SimCGC: DECREE OS model
javavm.py — SimJavaVM: Java VM environment
snimmuc_nxp.py — SimSnimmucNxp: NXP bare-metal
xbox.py — SimXbox: Xbox environment

## state_plugins/
plugin.py — SimStatePlugin base class
solver.py — SimSolver: constraint solver (claripy)
inspect.py — SimInspector: breakpoints
history.py — SimStateHistory: execution history
callstack.py — CallStack plugin
scratch.py — SimStateScratch: temp step data
posix.py — SimSystemPosix: file descriptors
filesystem.py — SimFilesystem
libc.py — SimStateLibc: libc state
globals.py — SimStateGlobals: dict-like storage
preconstrainer.py — Preconstrainer: constrain for tracing
unicorn_engine.py — Unicorn state plugin
uc_manager.py — Unicorn context manager
log.py — SimStateLog
sim_action.py — SimAction: recorded actions
sim_action_object.py — SimActionObject: tracked values
sim_event.py — SimEvent types
view.py — SimRegNameView/SimMemView
light_registers.py — LightRegisters: fast register storage
symbolizer.py — replace concrete with symbolic
cgc.py — CGC state plugin
gdb.py — GDB integration
debug_variables.py — DWARF variable tracking
edge_hitmap.py — edge hit counting
loop_data.py — loop iteration tracking
trace_additions.py — tracer additions
javavm_classloader.py — Java class loader
jni_references.py — JNI references
heap/: heap_base.py, heap_brk.py (brk-based), heap_freelist.py, heap_libc.py, heap_ptmalloc.py (ptmalloc2), utils.py

## storage/
file.py — SimFile, SimFileStream, SimPackets
memory_object.py — SimMemoryObject: stored values with metadata

## storage/memory_mixins/
memory_mixin.py — MemoryMixin base class
simple_interface_mixin.py — high-level load/store interface
address_concretization_mixin.py — symbolic address resolution
actions_mixin.py — SimAction recording
bvv_conversion_mixin.py — auto BVV conversion
conditional_store_mixin.py — conditional memory writes
default_filler_mixin.py — fill uninitialized memory
symbolic_merger_mixin.py — merge symbolic states
size_resolution_mixin.py — resolve symbolic sizes
simplification_mixin.py — simplify stored expressions
convenient_mappings_mixin.py — named region tracking
name_resolution_mixin.py — symbol name resolution
hex_dumper_mixin.py — hex dump support
dirty_addrs_mixin.py — track dirty addresses
clouseau_mixin.py — memory tracking/debugging
smart_find_mixin.py — pattern search in memory
unwrapper_mixin.py — unwrap SimActionObjects
top_merger_mixin.py — TOP value merging
multi_value_merger_mixin.py — multi-value merging
label_merger_mixin.py — label merging
underconstrained_mixin.py — underconstrained symex
slotted_memory.py — SlottedMemory: fixed-size slots
keyvalue_memory_mixin.py — key-value memory model
javavm_memory_mixin.py — Java memory model

## storage/memory_mixins/paged_memory/
paged_memory_mixin.py — PagedMemoryMixin: page-based CoW memory
paged_memory_multivalue_mixin.py — multi-value variant
stack_allocation_mixin.py — auto stack page allocation
privileged_mixin.py — permission checking
page_backer_mixins.py — CLE-backed pages
pages/: base.py, ultra_page.py (fast concrete), list_page.py (byte-level symbolic), mv_list_page.py (multi-value), permissions_mixin.py, cooperation.py, refcount_mixin.py, history_tracking_mixin.py, ispo_mixin.py, multi_values.py

## storage/memory_mixins/regioned_memory/
regioned_memory_mixin.py — RegionedMemory: abstract regions (VSA)
abstract_address_descriptor.py — abstract address descriptors
abstract_merger_mixin.py — abstract value merging
region_category_mixin.py — region category handling
region_data.py — region data storage
regioned_address_concretization_mixin.py — regioned address concretization
region_meta_mixin.py — region metadata
static_find_mixin.py — static pattern finding

## utils/
graph.py — graph: dominators, post-dom, loop detection
ail.py — AIL utilities; algo.py — algorithm utilities
balancer.py — constraint balancer; bits.py — bit manipulation
constants.py — constant values; cowdict.py — copy-on-write dict
cpp.py — C++ demangling; doms.py — dominator utilities
dynamic_dictlist.py — dict-list hybrid; endness.py — endianness conversion
enums_conv.py — enum conversion; env.py — environment helpers
formatting.py — output formatting; funcid.py — function ID helpers
lazy_import.py — lazy importing; library.py — library/symbol lookup
loader.py — loader utilities; mp.py — multiprocessing helpers
orderedset.py — OrderedSet; smart_cache.py — smart caching
strings.py — string utilities; tagged_interval_map.py — tagged interval map
timing.py — timing/profiling; types.py — type utilities; vex.py — VEX IR utilities
ssa/: tmp_uses_collector.py, vvar_uses_collector.py, vvar_extra_defs_collector.py

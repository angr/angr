API Reference
=============

.. automodule:: angr

Project
-------

.. automodule:: angr.project
.. automodule:: angr.factory
.. automodule:: angr.block

Plugin Ecosystem
----------------

.. automodule:: angr.misc.plugins

Program State
-------------
.. automodule:: angr.sim_state
.. automodule:: angr.sim_options
.. automodule:: angr.sim_state_options
.. automodule:: angr.state_plugins
.. automodule:: angr.state_plugins.plugin
.. automodule:: angr.state_plugins.inspect
.. automodule:: angr.state_plugins.libc
.. automodule:: angr.state_plugins.posix
.. automodule:: angr.state_plugins.filesystem
.. automodule:: angr.state_plugins.solver
.. automodule:: angr.state_plugins.log
.. automodule:: angr.state_plugins.callstack
.. automodule:: angr.state_plugins.light_registers
.. automodule:: angr.state_plugins.history
.. automodule:: angr.state_plugins.gdb
.. automodule:: angr.state_plugins.cgc
.. automodule:: angr.state_plugins.trace_additions
.. automodule:: angr.state_plugins.globals
.. automodule:: angr.state_plugins.uc_manager
.. automodule:: angr.state_plugins.scratch
.. automodule:: angr.state_plugins.preconstrainer
.. automodule:: angr.state_plugins.unicorn_engine
.. automodule:: angr.state_plugins.loop_data
.. automodule:: angr.state_plugins.concrete
.. automodule:: angr.state_plugins.javavm_classloader
.. automodule:: angr.state_plugins.jni_references
.. automodule:: angr.state_plugins.heap
.. automodule:: angr.state_plugins.heap.heap_base
.. automodule:: angr.state_plugins.heap.heap_brk
.. automodule:: angr.state_plugins.heap.heap_freelist
.. automodule:: angr.state_plugins.heap.heap_libc
.. automodule:: angr.state_plugins.heap.heap_ptmalloc
.. automodule:: angr.state_plugins.heap.utils
.. automodule:: angr.state_plugins.symbolizer
.. automodule:: angr.state_plugins.debug_variables

Storage
-------

.. automodule:: angr.storage
.. automodule:: angr.state_plugins.view
.. automodule:: angr.storage.file
.. automodule:: angr.storage.memory_object
.. automodule:: angr.storage.pcap
.. automodule:: angr.concretization_strategies

Memory Mixins
-------------

.. automodule:: angr.storage.memory_mixins
.. automodule:: angr.storage.memory_mixins.name_resolution_mixin
.. automodule:: angr.storage.memory_mixins.smart_find_mixin
.. automodule:: angr.storage.memory_mixins.default_filler_mixin
.. automodule:: angr.storage.memory_mixins.bvv_conversion_mixin
.. automodule:: angr.storage.memory_mixins.hex_dumper_mixin
.. automodule:: angr.storage.memory_mixins.underconstrained_mixin
.. automodule:: angr.storage.memory_mixins.simple_interface_mixin
.. automodule:: angr.storage.memory_mixins.actions_mixin
.. automodule:: angr.storage.memory_mixins.symbolic_merger_mixin
.. automodule:: angr.storage.memory_mixins.size_resolution_mixin
.. automodule:: angr.storage.memory_mixins.dirty_addrs_mixin
.. automodule:: angr.storage.memory_mixins.address_concretization_mixin
.. automodule:: angr.storage.memory_mixins.clouseau_mixin
.. automodule:: angr.storage.memory_mixins.conditional_store_mixin
.. automodule:: angr.storage.memory_mixins.label_merger_mixin
.. automodule:: angr.storage.memory_mixins.simplification_mixin
.. automodule:: angr.storage.memory_mixins.unwrapper_mixin
.. automodule:: angr.storage.memory_mixins.convenient_mappings_mixin
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.mv_list_page
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.multi_values
.. automodule:: angr.storage.memory_mixins.top_merger_mixin
.. automodule:: angr.storage.memory_mixins.multi_value_merger_mixin

.. automodule:: angr.storage.memory_mixins.paged_memory
.. automodule:: angr.storage.memory_mixins.paged_memory.paged_memory_mixin
.. automodule:: angr.storage.memory_mixins.paged_memory.page_backer_mixins
.. automodule:: angr.storage.memory_mixins.paged_memory.stack_allocation_mixin
.. automodule:: angr.storage.memory_mixins.paged_memory.privileged_mixin
.. automodule:: angr.storage.memory_mixins.paged_memory.pages
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.refcount_mixin
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.permissions_mixin
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.history_tracking_mixin
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.ispo_mixin
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.cooperation
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.list_page
.. automodule:: angr.storage.memory_mixins.paged_memory.pages.ultra_page

.. automodule:: angr.storage.memory_mixins.regioned_memory
.. automodule:: angr.storage.memory_mixins.regioned_memory.regioned_memory_mixin
.. automodule:: angr.storage.memory_mixins.regioned_memory.region_data
.. automodule:: angr.storage.memory_mixins.regioned_memory.region_category_mixin
.. automodule:: angr.storage.memory_mixins.regioned_memory.static_find_mixin
.. automodule:: angr.storage.memory_mixins.regioned_memory.abstract_address_descriptor
.. automodule:: angr.storage.memory_mixins.regioned_memory.region_meta_mixin
.. automodule:: angr.storage.memory_mixins.regioned_memory.abstract_merger_mixin
.. automodule:: angr.storage.memory_mixins.regioned_memory.regioned_address_concretization_mixin

.. automodule:: angr.storage.memory_mixins.slotted_memory

.. automodule:: angr.storage.memory_mixins.keyvalue_memory
.. automodule:: angr.storage.memory_mixins.keyvalue_memory.keyvalue_memory_mixin

.. automodule:: angr.storage.memory_mixins.javavm_memory
.. automodule:: angr.storage.memory_mixins.javavm_memory.javavm_memory_mixin

Concretization Strategies
-------------------------

.. automodule:: angr.concretization_strategies.single
.. automodule:: angr.concretization_strategies.eval
.. automodule:: angr.concretization_strategies.norepeats
.. automodule:: angr.concretization_strategies.solutions
.. automodule:: angr.concretization_strategies.nonzero_range
.. automodule:: angr.concretization_strategies.range
.. automodule:: angr.concretization_strategies.max
.. automodule:: angr.concretization_strategies.norepeats_range
.. automodule:: angr.concretization_strategies.nonzero
.. automodule:: angr.concretization_strategies.any
.. automodule:: angr.concretization_strategies.controlled_data
.. automodule:: angr.concretization_strategies.unlimited_range


Simulation Manager
------------------

.. automodule:: angr.sim_manager
.. automodule:: angr.state_hierarchy

Exploration Techniques
----------------------

.. automodule:: angr.exploration_techniques
.. automodule:: angr.exploration_techniques.timeout
.. automodule:: angr.exploration_techniques.dfs
.. automodule:: angr.exploration_techniques.explorer
.. automodule:: angr.exploration_techniques.lengthlimiter
.. automodule:: angr.exploration_techniques.manual_mergepoint
.. automodule:: angr.exploration_techniques.spiller
.. automodule:: angr.exploration_techniques.spiller_db
.. automodule:: angr.exploration_techniques.threading
.. automodule:: angr.exploration_techniques.veritesting
.. automodule:: angr.exploration_techniques.tracer
.. automodule:: angr.exploration_techniques.driller_core
.. automodule:: angr.exploration_techniques.slicecutor
.. automodule:: angr.exploration_techniques.director
.. automodule:: angr.exploration_techniques.oppologist
.. automodule:: angr.exploration_techniques.loop_seer
.. automodule:: angr.exploration_techniques.local_loop_seer
.. automodule:: angr.exploration_techniques.stochastic
.. automodule:: angr.exploration_techniques.unique
.. automodule:: angr.exploration_techniques.tech_builder
.. automodule:: angr.exploration_techniques.common
.. automodule:: angr.exploration_techniques.symbion
.. automodule:: angr.exploration_techniques.memory_watcher
.. automodule:: angr.exploration_techniques.bucketizer
.. automodule:: angr.exploration_techniques.suggestions

Simulation Engines
------------------

.. automodule:: angr.engines
.. automodule:: angr.engines.engine
.. automodule:: angr.engines.successors
.. automodule:: angr.engines.procedure
.. automodule:: angr.engines.hook
.. automodule:: angr.engines.syscall
.. automodule:: angr.engines.failure
.. automodule:: angr.engines.vex
.. automodule:: angr.engines.soot
.. automodule:: angr.engines.soot.engine
.. automodule:: angr.engines.unicorn
.. automodule:: angr.engines.concrete
.. automodule:: angr.engines.pcode
.. automodule:: angr.engines.pcode.engine
.. automodule:: angr.engines.pcode.lifter
.. automodule:: angr.engines.pcode.emulate
.. automodule:: angr.engines.pcode.behavior
.. automodule:: angr.engines.pcode.cc

Simulation Logging
------------------
.. automodule:: angr.state_plugins.sim_action
.. automodule:: angr.state_plugins.sim_action_object
.. automodule:: angr.state_plugins.sim_event

Procedures
----------
.. automodule:: angr.sim_procedure
.. automodule:: angr.procedures
.. automodule:: angr.procedures.stubs.format_parser
.. automodule:: angr.procedures.definitions

Calling Conventions and Types
-----------------------------
.. automodule:: angr.calling_conventions
.. automodule:: angr.sim_variable
.. automodule:: angr.sim_type
.. automodule:: angr.callable

Knowledge Base
--------------

.. automodule:: angr.knowledge_base
.. automodule:: angr.knowledge_base.knowledge_base
.. automodule:: angr.knowledge_plugins
.. automodule:: angr.knowledge_plugins.patches
.. automodule:: angr.knowledge_plugins.plugin
.. automodule:: angr.knowledge_plugins.callsite_prototypes
.. automodule:: angr.knowledge_plugins.cfg
.. automodule:: angr.knowledge_plugins.cfg.cfg_model
.. automodule:: angr.knowledge_plugins.cfg.memory_data
.. automodule:: angr.knowledge_plugins.cfg.cfg_manager
.. automodule:: angr.knowledge_plugins.cfg.cfg_node
.. automodule:: angr.knowledge_plugins.cfg.indirect_jump
.. automodule:: angr.knowledge_plugins.gotos
.. automodule:: angr.knowledge_plugins.types
.. automodule:: angr.knowledge_plugins.propagations
.. automodule:: angr.knowledge_plugins.comments
.. automodule:: angr.knowledge_plugins.data
.. automodule:: angr.knowledge_plugins.indirect_jumps
.. automodule:: angr.knowledge_plugins.labels
.. automodule:: angr.knowledge_plugins.functions
.. automodule:: angr.knowledge_plugins.functions.function_manager
    :members: FunctionManager
.. automodule:: angr.knowledge_plugins.functions.function
.. automodule:: angr.knowledge_plugins.functions.function_parser
.. automodule:: angr.knowledge_plugins.functions.soot_function
.. automodule:: angr.knowledge_plugins.variables
.. automodule:: angr.knowledge_plugins.variables.variable_access
.. automodule:: angr.knowledge_plugins.variables.variable_manager
.. automodule:: angr.knowledge_plugins.debug_variables
.. automodule:: angr.knowledge_plugins.structured_code
.. automodule:: angr.knowledge_plugins.structured_code.manager
.. automodule:: angr.knowledge_plugins.key_definitions
.. automodule:: angr.knowledge_plugins.key_definitions.atoms
.. automodule:: angr.knowledge_plugins.key_definitions.constants
.. automodule:: angr.knowledge_plugins.key_definitions.definition
.. automodule:: angr.knowledge_plugins.key_definitions.environment
.. automodule:: angr.knowledge_plugins.key_definitions.heap_address
.. automodule:: angr.knowledge_plugins.key_definitions.key_definition_manager
.. automodule:: angr.knowledge_plugins.key_definitions.live_definitions
.. automodule:: angr.knowledge_plugins.key_definitions.rd_model
.. automodule:: angr.knowledge_plugins.key_definitions.tag
.. automodule:: angr.knowledge_plugins.key_definitions.undefined
.. automodule:: angr.knowledge_plugins.key_definitions.unknown_size
.. automodule:: angr.knowledge_plugins.key_definitions.uses
.. automodule:: angr.knowledge_plugins.sync
.. automodule:: angr.knowledge_plugins.sync.sync_controller
.. automodule:: angr.knowledge_plugins.xrefs
.. automodule:: angr.knowledge_plugins.xrefs.xref
.. automodule:: angr.knowledge_plugins.xrefs.xref_types
.. automodule:: angr.knowledge_plugins.xrefs.xref_manager
.. automodule:: angr.code_location
.. automodule:: angr.keyed_region


Serialization
-------------

.. automodule:: angr.serializable
.. automodule:: angr.protos
.. automodule:: angr.vaults


Analysis
--------

.. automodule:: angr.analyses
.. automodule:: angr.analyses.analysis
.. automodule:: angr.analyses.forward_analysis
.. automodule:: angr.analyses.forward_analysis.forward_analysis
.. automodule:: angr.analyses.forward_analysis.job_info
.. automodule:: angr.analyses.forward_analysis.visitors
.. automodule:: angr.analyses.forward_analysis.visitors.call_graph
.. automodule:: angr.analyses.forward_analysis.visitors.function_graph
.. automodule:: angr.analyses.forward_analysis.visitors.graph
.. automodule:: angr.analyses.forward_analysis.visitors.loop
.. automodule:: angr.analyses.forward_analysis.visitors.single_node_graph
.. automodule:: angr.analyses.backward_slice
.. automodule:: angr.analyses.bindiff
.. automodule:: angr.analyses.boyscout
.. automodule:: angr.analyses.calling_convention
.. automodule:: angr.analyses.complete_calling_conventions
.. automodule:: angr.analyses.soot_class_hierarchy
.. automodule:: angr.analyses.cfg
.. automodule:: angr.analyses.cfg.cfb
.. automodule:: angr.analyses.cfg.cfg
.. automodule:: angr.analyses.cfg.cfg_emulated
.. automodule:: angr.analyses.cfg.cfg_base
.. automodule:: angr.analyses.cfg.cfg_fast
.. automodule:: angr.analyses.cfg.cfg_arch_options
.. automodule:: angr.analyses.cfg.cfg_job_base
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.amd64_elf_got
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.arm_elf_fast
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.x86_pe_iat
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.mips_elf_fast
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.x86_elf_pic_plt
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.default_resolvers
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.jumptable
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.const_resolver
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers.resolver
.. automodule:: angr.analyses.cfg.indirect_jump_resolvers
.. automodule:: angr.analyses.cfg.cfg_fast_soot
.. automodule:: angr.analyses.cfg.segment_list
.. automodule:: angr.analyses.cdg
.. automodule:: angr.analyses.datagraph_meta
.. automodule:: angr.analyses.code_tagging
.. automodule:: angr.angrdb
.. automodule:: angr.angrdb.db
.. automodule:: angr.angrdb.models
.. automodule:: angr.angrdb.serializers
.. automodule:: angr.angrdb.serializers.cfg_model
.. automodule:: angr.angrdb.serializers.comments
.. automodule:: angr.angrdb.serializers.funcs
.. automodule:: angr.angrdb.serializers.kb
.. automodule:: angr.angrdb.serializers.labels
.. automodule:: angr.angrdb.serializers.loader
.. automodule:: angr.angrdb.serializers.xrefs
.. automodule:: angr.angrdb.serializers.variables
.. automodule:: angr.angrdb.serializers.structured_code
.. automodule:: angr.analyses.decompiler.structuring.recursive_structurer
.. automodule:: angr.analyses.decompiler.structuring
.. automodule:: angr.analyses.decompiler.structuring.dream
.. automodule:: angr.analyses.decompiler.structuring.structurer_nodes
.. automodule:: angr.analyses.decompiler.structuring.structurer_base
.. automodule:: angr.analyses.decompiler.structuring.phoenix
.. automodule:: angr.analyses.decompiler
.. automodule:: angr.analyses.decompiler.ail_simplifier
.. automodule:: angr.analyses.decompiler.ailgraph_walker
.. automodule:: angr.analyses.decompiler.block_simplifier
.. automodule:: angr.analyses.decompiler.callsite_maker
.. automodule:: angr.analyses.decompiler.ccall_rewriters
.. automodule:: angr.analyses.decompiler.ccall_rewriters.rewriter_base
.. automodule:: angr.analyses.decompiler.ccall_rewriters.amd64_ccalls
.. automodule:: angr.analyses.decompiler.clinic
.. automodule:: angr.analyses.decompiler.condition_processor
.. automodule:: angr.analyses.decompiler.decompilation_options
.. automodule:: angr.analyses.decompiler.decompilation_cache
.. automodule:: angr.analyses.decompiler.decompiler
.. automodule:: angr.analyses.decompiler.empty_node_remover
.. automodule:: angr.analyses.decompiler.expression_narrower
.. automodule:: angr.analyses.decompiler.graph_region
.. automodule:: angr.analyses.decompiler.jump_target_collector
.. automodule:: angr.analyses.decompiler.jumptable_entry_condition_rewriter
.. automodule:: angr.analyses.decompiler.optimization_passes
.. automodule:: angr.analyses.decompiler.optimization_passes.const_derefs
.. automodule:: angr.analyses.decompiler.optimization_passes.eager_returns
.. automodule:: angr.analyses.decompiler.optimization_passes.optimization_pass
.. automodule:: angr.analyses.decompiler.optimization_passes.stack_canary_simplifier
.. automodule:: angr.analyses.decompiler.optimization_passes.base_ptr_save_simplifier
.. automodule:: angr.analyses.decompiler.optimization_passes.div_simplifier
.. automodule:: angr.analyses.decompiler.optimization_passes.ite_expr_converter
.. automodule:: angr.analyses.decompiler.optimization_passes.lowered_switch_simplifier
.. automodule:: angr.analyses.decompiler.optimization_passes.multi_simplifier
.. automodule:: angr.analyses.decompiler.optimization_passes.mod_simplifier
.. automodule:: angr.analyses.decompiler.optimization_passes.engine_base
.. automodule:: angr.analyses.decompiler.optimization_passes.expr_op_swapper
.. automodule:: angr.analyses.decompiler.optimization_passes.register_save_area_simplifier
.. automodule:: angr.analyses.decompiler.optimization_passes.ret_addr_save_simplifier
.. automodule:: angr.analyses.decompiler.optimization_passes.x86_gcc_getpc_simplifier
.. automodule:: angr.analyses.decompiler.peephole_optimizations
.. automodule:: angr.analyses.decompiler.peephole_optimizations.base
.. automodule:: angr.analyses.decompiler.region_identifier
.. automodule:: angr.analyses.decompiler.region_simplifiers
.. automodule:: angr.analyses.decompiler.region_simplifiers.cascading_cond_transformer
.. automodule:: angr.analyses.decompiler.region_simplifiers.cascading_ifs
.. automodule:: angr.analyses.decompiler.region_simplifiers.expr_folding
.. automodule:: angr.analyses.decompiler.region_simplifiers.goto
.. automodule:: angr.analyses.decompiler.region_simplifiers.if_
.. automodule:: angr.analyses.decompiler.region_simplifiers.ifelse
.. automodule:: angr.analyses.decompiler.region_simplifiers.loop
.. automodule:: angr.analyses.decompiler.region_simplifiers.node_address_finder
.. automodule:: angr.analyses.decompiler.region_simplifiers.region_simplifier
.. automodule:: angr.analyses.decompiler.region_simplifiers.switch_cluster_simplifier
.. automodule:: angr.analyses.decompiler.region_simplifiers.switch_expr_simplifier
.. automodule:: angr.analyses.decompiler.region_walker
.. automodule:: angr.analyses.decompiler.redundant_label_remover
.. automodule:: angr.analyses.decompiler.sequence_walker
.. automodule:: angr.analyses.decompiler.structured_codegen
.. automodule:: angr.analyses.decompiler.structured_codegen.base
.. automodule:: angr.analyses.decompiler.structured_codegen.c
.. automodule:: angr.analyses.decompiler.structured_codegen.dwarf_import
.. automodule:: angr.analyses.decompiler.structured_codegen.dummy
.. automodule:: angr.analyses.decompiler.utils
.. automodule:: angr.analyses.ddg
.. automodule:: angr.analyses.flirt
.. automodule:: angr.engines.light.data
.. automodule:: angr.engines.light
.. automodule:: angr.engines.light.engine
.. automodule:: angr.analyses.propagator
.. automodule:: angr.analyses.propagator.values
.. automodule:: angr.analyses.propagator.vex_vars
.. automodule:: angr.analyses.propagator.call_expr_finder
.. automodule:: angr.analyses.propagator.engine_base
.. automodule:: angr.analyses.propagator.engine_vex
.. automodule:: angr.analyses.propagator.engine_ail
.. automodule:: angr.analyses.propagator.outdated_definition_walker
.. automodule:: angr.analyses.propagator.tmpvar_finder
.. automodule:: angr.analyses.propagator.propagator
.. automodule:: angr.analyses.propagator.prop_value
.. automodule:: angr.analyses.propagator.top_checker_mixin
.. automodule:: angr.analyses.reaching_definitions
.. automodule:: angr.analyses.reaching_definitions.call_trace
.. automodule:: angr.analyses.reaching_definitions.engine_vex
.. automodule:: angr.analyses.reaching_definitions.reaching_definitions
.. automodule:: angr.analyses.reaching_definitions.dep_graph
.. automodule:: angr.analyses.reaching_definitions.heap_allocator
.. automodule:: angr.analyses.reaching_definitions.function_handler
.. automodule:: angr.analyses.reaching_definitions.rd_state
.. automodule:: angr.analyses.reaching_definitions.subject
.. automodule:: angr.analyses.reaching_definitions.engine_ail
.. automodule:: angr.analyses.cfg_slice_to_sink
.. automodule:: angr.analyses.cfg_slice_to_sink.cfg_slice_to_sink
.. automodule:: angr.analyses.cfg_slice_to_sink.graph
.. automodule:: angr.analyses.cfg_slice_to_sink.transitions
.. automodule:: angr.analyses.stack_pointer_tracker
.. automodule:: angr.analyses.variable_recovery.annotations
.. automodule:: angr.analyses.variable_recovery.variable_recovery_base
.. automodule:: angr.analyses.variable_recovery.variable_recovery_fast
.. automodule:: angr.analyses.variable_recovery.variable_recovery
.. automodule:: angr.analyses.variable_recovery.engine_ail
.. automodule:: angr.analyses.variable_recovery.engine_vex
.. automodule:: angr.analyses.variable_recovery.engine_base
.. automodule:: angr.analyses.variable_recovery.irsb_scanner
.. automodule:: angr.analyses.variable_recovery
.. automodule:: angr.analyses.typehoon.lifter
.. automodule:: angr.analyses.typehoon.simple_solver
.. automodule:: angr.analyses.typehoon.translator
.. automodule:: angr.analyses.typehoon.typevars
.. automodule:: angr.analyses.typehoon.typehoon
.. automodule:: angr.analyses.typehoon.typeconsts
.. automodule:: angr.analyses.typehoon
.. automodule:: angr.analyses.identifier.identify
.. automodule:: angr.analyses.loopfinder
.. automodule:: angr.analyses.loop_analysis
.. automodule:: angr.analyses.veritesting
.. automodule:: angr.analyses.vfg
.. automodule:: angr.analyses.vsa_ddg
.. automodule:: angr.analyses.vtable
.. automodule:: angr.analyses.find_objects_static
.. automodule:: angr.analyses.class_identifier
.. automodule:: angr.analyses.disassembly
.. automodule:: angr.analyses.disassembly_utils
.. automodule:: angr.analyses.reassembler
.. automodule:: angr.analyses.congruency_check
.. automodule:: angr.analyses.static_hooker
.. automodule:: angr.analyses.binary_optimizer
.. automodule:: angr.analyses.callee_cleanup_finder
.. automodule:: angr.analyses.dominance_frontier
.. automodule:: angr.analyses.init_finder
.. automodule:: angr.analyses.xrefs
.. automodule:: angr.analyses.proximity_graph
.. automodule:: angr.analyses.data_dep.data_dependency_analysis
.. automodule:: angr.analyses.data_dep.sim_act_location
.. automodule:: angr.analyses.data_dep.dep_nodes
.. automodule:: angr.analyses.data_dep
.. automodule:: angr.blade
.. automodule:: angr.slicer
.. automodule:: angr.annocfg
.. automodule:: angr.codenode


SimOS
-----

.. automodule:: angr.simos
.. automodule:: angr.simos.simos
.. automodule:: angr.simos.linux
.. automodule:: angr.simos.cgc
.. automodule:: angr.simos.userland
.. automodule:: angr.simos.windows
.. automodule:: angr.simos.javavm

Function Signature Matching
---------------------------

.. automodule:: angr.flirt
.. automodule:: angr.flirt.build_sig


Utils
-----
.. automodule:: angr.utils
.. automodule:: angr.utils.algo
.. automodule:: angr.utils.constants
.. automodule:: angr.utils.cowdict
.. automodule:: angr.utils.dynamic_dictlist
.. automodule:: angr.utils.enums_conv
.. automodule:: angr.utils.env
.. automodule:: angr.utils.graph
.. automodule:: angr.utils.lazy_import
.. automodule:: angr.utils.loader
.. automodule:: angr.utils.library
.. automodule:: angr.utils.timing
.. automodule:: angr.utils.formatting
.. automodule:: angr.utils.mp

Errors
------
.. automodule:: angr.errors

Distributed analysis
--------------------
.. automodule:: angr.distributed
.. automodule:: angr.distributed.server
.. automodule:: angr.distributed.worker

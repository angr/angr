List of State Options
=====================

State Modes
~~~~~~~~~~~

These may be enabled by passing ``mode=xxx`` to a state constructor.

.. list-table::
   :header-rows: 1

   * - Mode name
     - Description
   * - ``symbolic``
     - The default mode. Useful for most emulation and analysis tasks.
   * - ``symbolic_approximating``
     - Symbolic mode, but enables approximations for constraint solving.
   * - ``static``
     - A preset useful for static analysis. The memory model becomes an abstract
       region-mapping system, "fake return" successors skipping calls are added,
       and more.
   * - ``fastpath``
     - A preset for extremely lightweight static analysis. Executing will skip
       all intensive processing to give a quick view of the behavior of code.
   * - ``tracing``
     - A preset for attempting to execute concretely through a program with a
       given input. Enables unicorn, enables resilience options, and will
       attempt to emulate access violations correctly.


Option Sets
~~~~~~~~~~~

These are sets of options, found as ``angr.options.xxx``.

.. list-table::
   :header-rows: 1

   * - Set name
     - Description
   * - ``common_options``
     - Options necessary for basic execution
   * - ``symbolic``
     - Options necessary for basic symbolic execution
   * - ``resilience``
     - Options that harden angr's emulation against unsupported operations,
       attempting to carry on by treating the result as an unconstrained
       symbolic value and logging the occasion to ``state.history.events``.
   * - ``refs``
     - Options that cause angr to keep a log of all the memory, register, and
       temporary references complete with dependency information in
       ``history.actions``. This option consumes a lot of memory, so be careful!
   * - ``approximation``
     - Options that enable approximations of constraint solves via value-set
       analysis instead of calling into z3
   * - ``simplification``
     - Options that cause data to be run through z3's simplifiers before it
       reaches memory or register storage
   * - ``unicorn``
     - Options that enable the unicorn engine for executing on concrete data


Options
~~~~~~~

These are individual option objects, found as ``angr.options.XXX``.

.. list-table::
   :header-rows: 1

   * - Option name
     - Description
     - Sets
     - Modes
     - Implicit adds
   * - ``ABSTRACT_MEMORY``
     - Use ``SimAbstractMemory`` to model memory as discrete regions
     -
     - ``static``
     -
   * - ``ABSTRACT_SOLVER``
     - Allow splitting constraint sets during simplification
     -
     - ``static``
     -
   * - ``ACTION_DEPS``
     - Track dependencies in SimActions
     -
     -
     -
   * - ``APPROXIMATE_GUARDS``
     - Use VSA when evaluating guard conditions
     -
     -
     -
   * - ``APPROXIMATE_MEMORY_INDICES``
     - Use VSA when evaluating memory indices
     - ``approximation``
     - ``symbolic_approximating``
     -
   * - ``APPROXIMATE_MEMORY_SIZES``
     - Use VSA when evaluating memory load/store sizes
     - ``approximation``
     - ``symbolic_approximating``
     -
   * - ``APPROXIMATE_SATISFIABILITY``
     - Use VSA when evaluating state satisfiability
     - ``approximation``
     - ``symbolic_approximating``
     -
   * - ``AST_DEPS``
     - Enables dependency tracking for all claripy ASTs
     -
     -
     - During execution
   * - ``AUTO_REFS``
     - An internal option used to track dependencies in SimProcedures
     -
     -
     - During execution
   * - ``AVOID_MULTIVALUED_READS``
     - Return a symbolic value without touching memory for any read that has a symbolic address
     -
     - ``fastpath``
     -
   * - ``AVOID_MULTIVALUED_WRITES``
     - Do not perform any write that has a symbolic address
     -
     - ``fastpath``
     -
   * - ``BEST_EFFORT_MEMORY_STORING``
     - Handle huge writes of symbolic size by pretending they are actually smaller
     -
     - ``static``, ``fastpath``
     -
   * - ``BREAK_SIRSB_END``
     - Debug: trigger a breakpoint at the end of each block
     -
     -
     -
   * - ``BREAK_SIRSB_START``
     - Debug: trigger a breakpoint at the start of each block
     -
     -
     -
   * - ``BREAK_SIRSTMT_END``
     - Debug: trigger a breakpoint at the end of each IR statement
     -
     -
     -
   * - ``BREAK_SIRSTMT_START``
     - Debug: trigger a breakpoint at the start of each IR statement
     -
     -
     -
   * - ``BYPASS_ERRORED_IRCCALL``
     - Treat clean helpers that fail with errors as returning unconstrained symbolic values
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``BYPASS_ERRORED_IROP``
     - Treat operations that fail with errors as returning unconstrained symbolic values
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``BYPASS_UNSUPPORTED_IRCCALL``
     - Treat unsupported clean helpers as returning unconstrained symbolic values
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``BYPASS_UNSUPPORTED_IRDIRTY``
     - Treat unsupported dirty helpers as returning unconstrained symbolic values
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``BYPASS_UNSUPPORTED_IREXPR``
     - Treat unsupported IR expressions as returning unconstrained symbolic values
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``BYPASS_UNSUPPORTED_IROP``
     - Treat unsupported operations as returning unconstrained symbolic values
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``BYPASS_UNSUPPORTED_IRSTMT``
     - Treat unsupported IR statements as returning unconstrained symbolic values
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``BYPASS_UNSUPPORTED_SYSCALL``
     - Treat unsupported syscalls as returning unconstrained symbolic values
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``BYPASS_VERITESTING_EXCEPTIONS``
     - Discard emulation errors during veritesting
     - ``resilience``
     - ``fastpath``, ``tracing``
     -
   * - ``CACHELESS_SOLVER``
     - enable ``SolverCacheless``
     -
     -
     -
   * - ``CALLLESS``
     - Emulate call instructions as an unconstraining of the return value register
     -
     -
     -
   * - ``CGC_ENFORCE_FD``
     - CGC: make sure all reads and writes go to stdin and stdout, respectively
     -
     -
     -
   * - ``CGC_NON_BLOCKING_FDS``
     - CGC: always report "data available" in fdwait
     -
     -
     -
   * - ``CGC_NO_SYMBOLIC_RECEIVE_LENGTH``
     - CGC: always read the maximum amount of data requested in the receive syscall
     -
     -
     -
   * - ``COMPOSITE_SOLVER``
     - Enable ``SolverComposite`` for independent constraint set optimization
     - ``symbolic``
     - all except ``static``
     -
   * - ``CONCRETIZE``
     - Concretize all symbolic expressions encountered during emulation
     -
     -
     -
   * - ``CONCRETIZE_SYMBOLIC_FILE_READ_SIZES``
     - Concreteize the sizes of file reads
     -
     -
     -
   * - ``CONCRETIZE_SYMBOLIC_WRITE_SIZES``
     - Concretize the sizes of symbolic writes to memory
     -
     -
     -
   * - ``CONSERVATIVE_READ_STRATEGY``
     - Do not use SimConcretizationStrategyAny for reads; in case of read
       address concretization failures, return an unconstrained symbolic value
     -
     -
     -
   * - ``CONSERVATIVE_WRITE_STRATEGY``
     - Do not use SimConcretizationStrategyAny for writes; in case of write
       address concretization failures, treat the store as a no-op
     -
     -
     -
   * - ``CONSTRAINT_TRACKING_IN_SOLVER``
     - Set ``track=True`` for making claripy Solvers; enable use of
       ``unsat_core``
     -
     -
     -
   * - ``COW_STATES``
     - Copy states instead of mutating the initial state directly
     - ``common_options``
     - all
     -
   * - ``DOWNSIZE_Z3``
     - Downsize the claripy solver whenever possible to save memory
     -
     -
     -
   * - ``DO_CCALLS``
     - Perform IR clean calls
     - ``symbolic``
     - all except ``fastpath``
     -
   * - ``DO_GETS``
     - Perform IR register reads
     - ``common_options``
     - all
     -
   * - ``DO_LOADS``
     - Perform IR memory loads
     - ``common_options``
     - all
     -
   * - ``DO_OPS``
     - Perform IR computation operations
     - ``common_options``
     - all
     -
   * - ``DO_PUTS``
     - Perform IR register writes
     - ``common_options``
     - all
     -
   * - ``DO_RET_EMULATION``
     - For each ``Ijk_Call`` successor, add a corresponding ``Ijk_FakeRet``
       successor
     -
     - ``static``, ``fastpath``
     -
   * - ``DO_STORES``
     - Perform IR memory stores
     - ``common_options``
     - all
     -
   * - ``EFFICIENT_STATE_MERGING``
     - Keep in memory any state that might be a common ancestor in a merge
     -
     -
     - Veritesting
   * - ``ENABLE_NX``
     - When in conjunction with ``STRICT_PAGE_ACCESS``, raise a
       SimSegfaultException on executing non-executable memory
     -
     -
     - Automatically if supported
   * - ``EXCEPTION_HANDLING``
     - Ask all SimExceptions raised during execution to be handled by the SimOS
     -
     - ``tracing``
     -
   * - ``FAST_MEMORY``
     - Use ``SimFastMemory`` for memory storage
     -
     -
     -
   * - ``FAST_REGISTERS``
     - Use ``SimFastMemory`` for register storage
     -
     - ``fastpath``
     -
   * - ``INITIALIZE_ZERO_REGISTERS``
     - Treat the initial value of registers as zero instead of unconstrained
       symbolic
     - ``unicorn``
     - ``tracing``
     -
   * - ``KEEP_IP_SYMBOLIC``
     - Don't try to concretize successor states with symbolic instruction
       pointers
     -
     -
     -
   * - ``KEEP_MEMORY_READS_DISCRETE``
     - In abstract memory, handle failed loads by returning a DCIS?
     -
     -
     -
   * - ``LAZY_SOLVES``
     - Don't check satisfiability until absolutely necessary
     -
     -
     -
   * - ``MEMORY_SYMBOLIC_BYTES_MAP``
     - Maintain a mapping of symbolic variable to which memory address it
       "really" corresponds to, at the paged memory level?
     -
     -
     -
   * - ``NO_SYMBOLIC_JUMP_RESOLUTION``
     - Do not attempt to flatten symbolic-ip successors into discrete targets
     -
     - ``fastpath``
     -
   * - ``NO_SYMBOLIC_SYSCALL_RESOLUTION``
     - Do not attempt to flatten symbolic-syscall-number successors into
       discrete targets
     -
     - ``fastpath``
     -
   * - ``OPTIMIZE_IR``
     - Use LibVEX's optimization
     - ``common_options``
     - all
     -
   * - ``REGION_MAPPING``
     - Maintain a mapping of symbolic variable to which memory region it
       corresponds to, at the abstract memory level
     -
     - ``static``
     -
   * - ``REPLACEMENT_SOLVER``
     - Enable ``SolverReplacement``
     -
     -
     -
   * - ``REVERSE_MEMORY_HASH_MAP``
     - Maintain a mapping from AST hash to which addresses it is present in
     -
     -
     -
   * - ``REVERSE_MEMORY_NAME_MAP``
     - Maintain a mapping from symbolic variable name to which addresses it is
       present in, required for ``memory.replace_all``
     -
     - ``static``
     -
   * - ``SIMPLIFY_CONSTRAINTS``
     - Run added constraints through z3's simplifcation
     -
     -
     -
   * - ``SIMPLIFY_EXIT_GUARD``
     - Run branch guards through z3's simplification
     -
     -
     -
   * - ``SIMPLIFY_EXIT_STATE``
     - Perform simplification on all successor states generated
     -
     -
     -
   * - ``SIMPLIFY_EXIT_TARGET``
     - Run jump/call/branch targets through z3's simplification
     -
     -
     -
   * - ``SIMPLIFY_EXPRS``
     - Run the results of IR expressions through z3's simplification
     -
     -
     -
   * - ``SIMPLIFY_MEMORY_READS``
     - Run the results of memory reads through z3's simplification
     -
     -
     -
   * - ``SIMPLIFY_MEMORY_WRITES``
     - Run values stored to memory through z3's simplification
     - ``simplification``, ``common_options``
     - ``symbolic``, ``symbolic_approximating``, ``tracing``
     -
   * - ``SIMPLIFY_REGISTER_READS``
     - Run values read from registers through z3's simplification
     -
     -
     -
   * - ``SIMPLIFY_REGISTER_WRITES``
     - Run values written to registers through z3's simplification
     - ``simplification``, ``common_options``
     - ``symbolic``, ``symbolic_approximating``, ``tracing``
     -
   * - ``SIMPLIFY_RETS``
     - Run values returned from SimProcedures through z3's simplification
     -
     -
     -
   * - ``STRICT_PAGE_ACCESS``
     - Raise a SimSegfaultException when attempting to interact with memory in a
       way not permitted by the current permissions
     -
     - ``tracing``
     -
   * - ``SUPER_FASTPATH``
     - Only execute the last four instructions of each block
     -
     -
     -
   * - ``SUPPORT_FLOATING_POINT``
     - When disabled, throw an UnsupportedIROpError when encountering floating
       point operations
     - ``common_options``
     - all
     -
   * - ``SYMBOLIC``
     - Enable constraint solving?
     - ``symbolic``
     - ``symbolic``, ``symbolic_approximating``, ``fastpath``
     -
   * - ``SYMBOLIC_INITIAL_VALUES``
     - make ``state.solver.Unconstrained`` return a symbolic value instead of
       zero
     - ``symbolic``
     - all
     -
   * - ``SYMBOLIC_TEMPS``
     - Treat each IR temporary as a symbolic variable; treat stores to them as
       constraint addition
     -
     -
     -
   * - ``SYMBOLIC_WRITE_ADDRESSES``
     - Allow writes with symbolic addresses to be processed by concretization
       strategies; when disabled, only allow for variables annotated with the
       "multiwrite" annotation
     -
     -
     -
   * - ``TRACK_CONSTRAINTS``
     - When disabled, don't keep any constraints added to the state
     - ``symbolic``
     - all
     -
   * - ``TRACK_CONSTRAINT_ACTIONS``
     - Keep a SimAction for each constraint added
     - ``refs``
     -
     -
   * - ``TRACK_JMP_ACTIONS``
     - Keep a SimAction for each jump or branch
     - ``refs``
     -
     -
   * - ``TRACK_MEMORY_ACTIONS``
     - Keep a SimAction for each memory read and write
     - ``refs``
     -
     -
   * - ``TRACK_MEMORY_MAPPING``
     - Keep track of which pages are mapped into memory and which are not
     - ``common_options``
     - all
     -
   * - ``TRACK_OP_ACTIONS``
     - Keep a SimAction for each IR operation
     -
     - ``fastpath``
     -
   * - ``TRACK_REGISTER_ACTIONS``
     - Keep a SimAction for each register read and write
     - ``refs``
     -
     -
   * - ``TRACK_SOLVER_VARIABLES``
     - Maintain a listing of all the variables in all the constraints in the solver
     -
     -
     -
   * - ``TRACK_TMP_ACTIONS``
     - Keep a SimAction for each temporary variable read and write
     - ``refs``
     -
     -
   * - ``TRUE_RET_EMULATION_GUARD``
     - With ``DO_RET_EMULATION``, add fake returns with guard condition true
       instead of false
     -
     - ``static``
     -
   * - ``UNDER_CONSTRAINED_SYMEXEC``
     - Enable under-constrained symbolic execution
     -
     -
     -
   * - ``UNICORN``
     - Use unicorn engine to execute symbolically when data is concrete
     - ``unicorn``
     - ``tracing``
     - Oppologist
   * - ``UNICORN_AGGRESSIVE_CONCRETIZATION``
     - Concretize any register variable unicorn tries to access
     -
     -
     - Oppologist
   * - ``UNICORN_HANDLE_TRANSMIT_SYSCALL``
     - CGC: handle the transmit syscall without leaving unicorn
     - ``unicorn``
     - ``tracing``
     -
   * - ``UNICORN_SYM_REGS_SUPPORT``
     - Attempt to stay in unicorn even in the presence of symbolic registers by
       checking that the tainted registers are unused at every step
     - ``unicorn``
     - ``tracing``
     -
   * - ``UNICORN_THRESHOLD_CONCRETIZATION``
     - Concretize variables if they prevent unicorn from executing too often
     -
     -
     -
   * - ``UNICORN_TRACK_BBL_ADDRS``
     - Keep ``state.history.bbl_addrs`` up to date when using unicorn
     - ``unicorn``
     - ``tracing``
     -
   * - ``UNICORN_TRACK_STACK_POINTERS``
     - Track a list of the stack pointer's value at each block in
       ``state.scratch.stack_pointer_list``
     - ``unicorn``
     -
     -
   * - ``UNICORN_ZEROPAGE_GUARD``
     - Prevent unicorn from mapping the zero page into memory
     -
     -
     -
   * - ``UNINITIALIZED_ACCESS_AWARENESS``
     - Broken/unused?
     -
     -
     -
   * - ``UNSUPPORTED_BYPASS_ZERO_DEFAULT``
     - When using the resilience options, return zero instead of an
       unconstrained symbol
     -
     -
     -
   * - ``USE_SIMPLIFIED_CCALLS``
     - Use a "simplified" set of ccalls optimized for specific cases
     -
     - ``static``
     -
   * - ``USE_SYSTEM_TIMES``
     - In library functions and syscalls and hardware instructions accessing
       clock data, retrieve the real value from the host system.
     -
     - ``tracing``
     -
   * - ``VALIDATE_APPROXIMATIONS``
     - Debug: When performing approximations, ensure that the approximation is
       sound by calling into z3
     -
     -
     -
   * - ``ZERO_FILL_UNCONSTRAINED_MEMORY``
     - Make the value of memory read from an uninitialized address zero instead
       of an unconstrained symbol
     -
     - ``tracing``
     -


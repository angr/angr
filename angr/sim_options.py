# This module contains the analysis options.
# All variables with names of all caps will be registered as a state option to SimStateOptions.

import string
from .sim_state_options import SimStateOptions

# This option controls whether or not constraints are tracked in the analysis.
TRACK_CONSTRAINTS = "TRACK_CONSTRAINTS"

# This option controls whether or not various entities (IRExpr constants, reads, writes, etc) get simplified
# automatically
SIMPLIFY_EXPRS = "SIMPLIFY_EXPRS"
SIMPLIFY_MEMORY_READS = "SIMPLIFY_MEMORY_READS"
SIMPLIFY_MEMORY_WRITES = "SIMPLIFY_MEMORY_WRITES"
SIMPLIFY_REGISTER_READS = "SIMPLIFY_REGISTER_READS"
SIMPLIFY_REGISTER_WRITES = "SIMPLIFY_REGISTER_WRITES"
SIMPLIFY_RETS = "SIMPLIFY_RETS"
SIMPLIFY_EXIT_STATE = "SIMPLIFY_EXIT_STATE"
SIMPLIFY_EXIT_TARGET = "SIMPLIFY_EXIT_TARGET"
SIMPLIFY_EXIT_GUARD = "SIMPLIFY_EXIT_GUARD"
SIMPLIFY_CONSTRAINTS = "SIMPLIFY_CONSTRAINTS"
SIMPLIFY_MERGED_CONSTRAINTS = "SIMPLIFY_MERGED_CONSTRAINTS"

# This option controls whether the helper functions are actually executed for CCALL expressions.
# Without this, the arguments are parsed, but the calls aren't executed, and an unconstrained symbolic
# variable is returned, instead.
DO_CCALLS = "DO_CCALLS"

# Whether we should use the simplified ccalls or not.
USE_SIMPLIFIED_CCALLS = "USE_SIMPLIFIED_CCALLS"

# This option controls whether or not emulated exits and coderefs are added from a call instruction to its ret site.
DO_RET_EMULATION = "DO_RET_EMULATION"

# If this option is present, the guards to emulated ret exits are True instead of False
TRUE_RET_EMULATION_GUARD = "TRUE_RET_EMULATION_GUARD"

# This option causes the analysis to immediately concretize any symbolic value that it comes across
CONCRETIZE = "CONCRETIZE"

# This option prevents angr from doing hundreds of constraint solves to resolve symbolic jump targets
NO_SYMBOLIC_JUMP_RESOLUTION = "NO_SYMBOLIC_JUMP_RESOLUTION"

# This option prevents angr from doing hundreds of constraint solves when it hits a symbolic syscall
NO_SYMBOLIC_SYSCALL_RESOLUTION = "NO_SYMBOLIC_SYSCALL_RESOLUTION"

# The absense of this option causes the analysis to avoid reasoning about most symbolic values.
SYMBOLIC = "SYMBOLIC"

# This variable causes claripy to use a string solver (CVC4)
STRINGS_ANALYSIS = "STRINGS_ANALYSIS"

# Generate symbolic values for non-existent values. The absence of this option causes Unconstrained() to return default
# concrete values (like 0)
SYMBOLIC_INITIAL_VALUES = "SYMBOLIC_INITIAL_VALUES"

# this causes angr to use SimAbstractMemory for the memory region
ABSTRACT_MEMORY = "ABSTRACT_MEMORY"

# This causes symbolic memory to avoid performing symbolic reads and writes. Unconstrained results
# are returned instead, if these options are present.
AVOID_MULTIVALUED_READS = "AVOID_MULTIVALUED_READS"
AVOID_MULTIVALUED_WRITES = "AVOID_MULTIVALUED_WRITES"

# This option concretizes symbolically sized writes
CONCRETIZE_SYMBOLIC_WRITE_SIZES = "CONCRETIZE_SYMBOLIC_WRITE_SIZES"

# This option concretizes the read size if it's symbolic from the file
CONCRETIZE_SYMBOLIC_FILE_READ_SIZES = "CONCRETIZE_SYMBOLIC_FILE_READ_SIZES"

# If absent, treat the end of files as a frontier at which new data will be created
# If present, treat the end of files as an EOF
FILES_HAVE_EOF = "FILES_HAVE_EOF"
UNKNOWN_FILES_HAVE_EOF = FILES_HAVE_EOF

# Attempting to open an unkown file will result in creating it with a symbolic length
ALL_FILES_EXIST = "ALL_FILES_EXIST"

# Reads from devices will have a symbolic size
SHORT_READS = "SHORT_READS"

# This causes angr to support fully symbolic writes. It is very likely that speed will suffer.
SYMBOLIC_WRITE_ADDRESSES = "SYMBOLIC_WRITE_ADDRESSES"

# This causes symbolic memory to avoid concretizing memory address to a single value when the
# range check fails.
CONSERVATIVE_WRITE_STRATEGY = "CONSERVATIVE_WRITE_STRATEGY"
CONSERVATIVE_READ_STRATEGY = "CONSERVATIVE_READ_STRATEGY"

# This enables dependency tracking for all Claripy ASTs.
AST_DEPS = "AST_DEPS"

# This controls whether the temps are treated as symbolic values (for easier debugging) or just written as the z3 values
SYMBOLIC_TEMPS = "SYMBOLIC_TEMPS"

# These are options for tracking various types of actions
TRACK_MEMORY_ACTIONS = "TRACK_MEMORY_ACTIONS"
TRACK_REGISTER_ACTIONS = "TRACK_REGISTER_ACTIONS"
TRACK_TMP_ACTIONS = "TRACK_TMP_ACTIONS"
TRACK_JMP_ACTIONS = "TRACK_JMP_ACTIONS"
TRACK_CONSTRAINT_ACTIONS = "TRACK_CONSTRAINT_ACTIONS"
# note that TRACK_OP_ACTIONS is not enabled in symbolic mode by default, since Yan is worried about its performance
# impact. someone should measure it and make a final decision.
TRACK_OP_ACTIONS = "TRACK_OP_ACTIONS"

# track the history of actions through a path (multiple states). This action affects things on the angr level
TRACK_ACTION_HISTORY = "TRACK_ACTION_HISTORY"

# track memory mapping and permissions
TRACK_MEMORY_MAPPING = "TRACK_MEMORY_MAPPING"

# track constraints in solver. This is required to enable unsat_core()
CONSTRAINT_TRACKING_IN_SOLVER = "CONSTRAINT_TRACKING_IN_SOLVER"

# this is an internal option to automatically track dependencies in SimProcedures
AUTO_REFS = "AUTO_REFS"
ADD_AUTO_REFS = "ADD_AUTO_REFS"

# Whether we should track dependencies in SimActions
# If none of the ref options above exist, this option does nothing
ACTION_DEPS = "ACTION_DEPS"

# This enables the tracking of reverse mappings (name->addr and hash->addr) in SimSymbolicMemory
REVERSE_MEMORY_NAME_MAP = "REVERSE_MEMORY_NAME_MAP"
REVERSE_MEMORY_HASH_MAP = "REVERSE_MEMORY_HASH_MAP"

# This enables tracking of which bytes in the state are symbolic
MEMORY_SYMBOLIC_BYTES_MAP = "MEMORY_SYMBOLIC_BYTES_MAP"

# this makes engine copy states
COPY_STATES = "COPY_STATES"
COW_STATES = COPY_STATES

# this replaces calls with an unconstraining of the return register
CALLLESS = "CALLLESS"

# these enables independent constraint set optimizations. The first is a master toggle, and the second controls
# splitting constraint sets during simplification
COMPOSITE_SOLVER = "COMPOSITE_SOLVER"
ABSTRACT_SOLVER = "ABSTRACT_SOLVER"

# this stops SimRun for checking the satisfiability of successor states
LAZY_SOLVES = "LAZY_SOLVES"

# This makes angr downsize solvers wherever reasonable.
DOWNSIZE_Z3 = "DOWNSIZE_Z3"

# Turn-on superfastpath mode
SUPER_FASTPATH = "SUPER_FASTPATH"

# use FastMemory for memory
FAST_MEMORY = "FAST_MEMORY"

# use FastMemory for registers
FAST_REGISTERS = "FAST_REGISTERS"

# Under-constrained symbolic execution
UNDER_CONSTRAINED_SYMEXEC = "UNDER_CONSTRAINED_SYMEXEC"

# enable unicorn engine
UNICORN = "UNICORN"
UNICORN_ZEROPAGE_GUARD = "UNICORN_ZEROPAGE_GUARD"
UNICORN_SYM_REGS_SUPPORT = "UNICORN_SYM_REGS_SUPPORT"
UNICORN_TRACK_BBL_ADDRS = "UNICORN_TRACK_BBL_ADDRS"
UNICORN_TRACK_STACK_POINTERS = "UNICORN_TRACK_STACK_POINTERS"

# concretize symbolic data when we see it "too often"
UNICORN_THRESHOLD_CONCRETIZATION = "UNICORN_THRESHOLD_CONCRETIZATION"

# aggressively concretize symbolic data when we see it in unicorn
UNICORN_AGGRESSIVE_CONCRETIZATION = "UNICORN_AGGRESSIVE_CONCRETIZATION"

UNICORN_HANDLE_CGC_RANDOM_SYSCALL = "UNICORN_HANDLE_CGC_RANDOM_SYSCALL"
UNICORN_HANDLE_CGC_RECEIVE_SYSCALL = "UNICORN_HANDLE_CGC_RECEIVE_SYSCALL"
UNICORN_HANDLE_CGC_TRANSMIT_SYSCALL = "UNICORN_HANDLE_CGC_TRANSMIT_SYSCALL"

# Indicates if symbolic addresses should be handled in unicorn or not
UNICORN_HANDLE_SYMBOLIC_ADDRESSES = "UNICORN_HANDLE_SYMBOLIC_ADDRESSES"

# Indicates if symbolic conditions should be handled in unicorn or not
UNICORN_HANDLE_SYMBOLIC_CONDITIONS = "UNICORN_HANDLE_SYMBOLIC_CONDITIONS"

# Handle syscalls in unicorn even if arguments are symbolic
UNICORN_HANDLE_SYMBOLIC_SYSCALLS = "UNICORN_HANDLE_SYMBOLIC_SYSCALLS"

# floating point support
SUPPORT_FLOATING_POINT = "SUPPORT_FLOATING_POINT"

# Turn on memory region mapping logging
REGION_MAPPING = "REGION_MAPPING"

# Resilience options
BYPASS_UNSUPPORTED_IROP = "BYPASS_UNSUPPORTED_IROP"
BYPASS_ERRORED_IROP = "BYPASS_ERRORED_IROP"
BYPASS_UNSUPPORTED_IREXPR = "BYPASS_UNSUPPORTED_IREXPR"
BYPASS_UNSUPPORTED_IRSTMT = "BYPASS_UNSUPPORTED_IRSTMT"
BYPASS_UNSUPPORTED_IRDIRTY = "BYPASS_UNSUPPORTED_IRDIRTY"
BYPASS_UNSUPPORTED_IRCCALL = "BYPASS_UNSUPPORTED_IRCCALL"
BYPASS_ERRORED_IRCCALL = "BYPASS_ERRORED_IRCCALL"
BYPASS_UNSUPPORTED_SYSCALL = "BYPASS_UNSUPPORTED_SYSCALL"
BYPASS_ERRORED_IRSTMT = "BYPASS_ERRORED_IRSTMT"
UNSUPPORTED_BYPASS_ZERO_DEFAULT = "UNSUPPORTED_BYPASS_ZERO_DEFAULT"
# Concretize (parts of)unsupported IROPs
UNSUPPORTED_FORCE_CONCRETIZE = "UNSUPPORTED_FORCE_CONCRETIZE"

UNINITIALIZED_ACCESS_AWARENESS = "UNINITIALIZED_ACCESS_AWARENESS"
BEST_EFFORT_MEMORY_STORING = "BEST_EFFORT_MEMORY_STORING"

# Approximation options (to optimize symbolic execution)
APPROXIMATE_GUARDS = "APPROXIMATE_GUARDS"
APPROXIMATE_SATISFIABILITY = "APPROXIMATE_SATISFIABILITY"  # does GUARDS and the rest of the constraints
APPROXIMATE_MEMORY_SIZES = "APPROXIMATE_MEMORY_SIZES"
APPROXIMATE_MEMORY_INDICES = "APPROXIMATE_MEMORY_INDICES"
VALIDATE_APPROXIMATIONS = "VALIDATE_APPROXIMATIONS"

# use an experimental replacement solver
REPLACEMENT_SOLVER = "REPLACEMENT_SOLVER"

# use a cache-less solver in claripy
CACHELESS_SOLVER = "CACHELESS_SOLVER"

# IR optimization
OPTIMIZE_IR = "OPTIMIZE_IR"
NO_CROSS_INSN_OPT = "NO_CROSS_INSN_OPT"

SPECIAL_MEMORY_FILL = "SPECIAL_MEMORY_FILL"

# using this option the value inside the register ip is kept symbolic
KEEP_IP_SYMBOLIC = "KEEP_IP_SYMBOLIC"

# Do not try to concretize a symbolic IP. With this option, all states with symbolic IPs will be seen as unconstrained.
NO_IP_CONCRETIZATION = "NO_IP_CONCRETIZATION"

# Do not union values from different locations when reading from the memory for a reduced loss in precision
# It is only applied to SimAbstractMemory
KEEP_MEMORY_READS_DISCRETE = "KEEP_MEMORY_READS_DISCRETE"

# Raise a SimSegfaultError on illegal memory accesses
STRICT_PAGE_ACCESS = "STRICT_PAGE_ACCESS"

# Raise a SimSegfaultError when executing nonexecutable memory
ENABLE_NX = "ENABLE_NX"

# Ask the SimOS to handle segfaults
EXCEPTION_HANDLING = "EXCEPTION_HANDLING"

# Use system timestamps in simprocedures instead of returning symbolic values
USE_SYSTEM_TIMES = "USE_SYSTEM_TIMES"

# Track variables in state.solver.all_variables
TRACK_SOLVER_VARIABLES = "TRACK_SOLVER_VARIABLES"

# Efficient state merging requires potential state ancestors being kept in memory
EFFICIENT_STATE_MERGING = "EFFICIENT_STATE_MERGING"

# Return 0 any unspecified bytes in memory/registers
ZERO_FILL_UNCONSTRAINED_MEMORY = "ZERO_FILL_UNCONSTRAINED_MEMORY"
ZERO_FILL_UNCONSTRAINED_REGISTERS = "ZERO_FILL_UNCONSTRAINED_REGISTERS"
INITIALIZE_ZERO_REGISTERS = ZERO_FILL_UNCONSTRAINED_REGISTERS

# Return a new symbolic variable for any unspecified bytes in memory/registers. If neither these nor the above options
# are specified, a warning will be issued and an unconstrained symbolic variable will be generated
SYMBOL_FILL_UNCONSTRAINED_MEMORY = "SYMBOL_FILL_UNCONSTRAINED_MEMORY"
SYMBOL_FILL_UNCONSTRAINED_REGISTERS = "SYMBOL_FILL_UNCONSTRAINED_REGISTERS"

# Attempt to support wacky ops not found in libvex
EXTENDED_IROP_SUPPORT = "EXTENDED_IROP_SUPPORT"

# For each division operation, produce a successor state with the constraint that the divisor is zero
PRODUCE_ZERODIV_SUCCESSORS = "PRODUCE_ZERODIV_SUCCESSORS"

SYNC_CLE_BACKEND_CONCRETE = "SYNC_CLE_BACKEND_CONCRETE"

# Allow POSIX API send() to fail
ALLOW_SEND_FAILURES = "ALLOW_SEND_FAILURES"

# Use hybrid solver
HYBRID_SOLVER = "HYBRID_SOLVER"

# This tells the hybrid solver to use the approximate backend first. The exact backend will be used
# only if the number of possible approximate solutions is greater than what was request by user.
# Note, that this option will only take effect if a hybrid solver used.
APPROXIMATE_FIRST = "APPROXIMATE_FIRST"

# Disable optimizations based on symbolic memory bytes being single-valued in SimSymbolicMemory. This is useful in
# tracing mode since such optimizations are unreliable since preconstraints will be removed after tracing is done.
SYMBOLIC_MEMORY_NO_SINGLEVALUE_OPTIMIZATIONS = "SYMBOLIC_MEMORY_NO_SINGLEVALUE_OPTIMIZATIONS"

# When SimMemory.find() is called, apply a strict size-limit condition check. This is mainly used in tracing mode. When
# this option is enabled, constraint replacement and solves will kick in when testing the byte-equivalence constraints
# built in SimMemory._find(), and less cases will be satisfiable. In tracing mode, this means the character to find will
# have to show up at the exact location as specified in the concrete input. When this option is disabled, constraint
# replacement and solves will not be triggered when testing byte-equivalence constraints, which in tracing mode, will
# allow some flexibility regarding the position of character to find at the cost of larger constraints built in
# SimMemory._find() and more time and memory consumption.
MEMORY_FIND_STRICT_SIZE_LIMIT = "MEMORY_FIND_STRICT_SIZE_LIMIT"

# return unconstrained symbols from cpuid
CPUID_SYMBOLIC = "CPUID_SYMBOLIC"

#
# CGC specific state options
#

CGC_ZERO_FILL_UNCONSTRAINED_MEMORY = ZERO_FILL_UNCONSTRAINED_MEMORY
# Make sure the receive syscall always read as many bytes as the program wants
CGC_NO_SYMBOLIC_RECEIVE_LENGTH = "CGC_NO_SYMBOLIC_RECEIVE_LENGTH"
BYPASS_VERITESTING_EXCEPTIONS = "BYPASS_VERITESTING_EXCEPTIONS"
# Make sure filedescriptors on transmit and receive are always 1 and 0
CGC_ENFORCE_FD = "CGC_ENFORCE_FD"
# FDWAIT will always return FDs as non blocking
CGC_NON_BLOCKING_FDS = "CGC_NON_BLOCKING_FDS"

# Allows memory breakpoints to get more accurate sizes in case of reading large chunks
# Sacrafice performance for more fine tune memory read size
MEMORY_CHUNK_INDIVIDUAL_READS = "MEMORY_CHUNK_INDIVIDUAL_READS"

# Synchronize memory mapping reported by angr with the concrete process.
SYMBION_SYNC_CLE = "SYMBION_SYNC_CLE"
# Removes stubs SimProc on synchronization with concrete process.
# We will execute SimProc for functions for which we have one, and the real function for the one we have not.
SYMBION_KEEP_STUBS_ON_SYNC = "SYMBION_KEEP_STUBS_ON_SYNC"

# Activate the heuristic that tries to understand if an unknown method (e. g. library call) gets or sets an
# attribute inside the object. Turn on this option to have a better approximation of the internal structure of the
# symbolic object.
JAVA_IDENTIFY_GETTER_SETTER = "JAVA_IDENTIFY_GETTER_SETTER"
# Activate attributes tracking for objects.
JAVA_TRACK_ATTRIBUTES = "JAVA_TRACK_ATTRIBUTES"

#
# Register those variables as Boolean state options
#

_g = globals().copy()
for k, v in _g.items():
    if all([char in string.ascii_uppercase + "_" + string.digits for char in k]) and type(v) is str:
        if k in (
            "UNKNOWN_FILES_HAVE_EOF",
            "CGC_ZERO_FILL_UNCONSTRAINED_MEMORY",
            "COW_STATES",
            "INITIALIZE_ZERO_REGISTERS",
        ):
            # UNKNOWN_FILES_HAVE_EOF == FILES_HAVE_EOF
            # CGC_ZERO_FILL_UNCONSTRAINED_MEMORY == ZERO_FILL_UNCONSTRAINED_MEMORY
            # INITIALIZE_ZERO_REGISTERS == ZERO_FILL_UNCONSTRAINED_REGISTERS
            continue
        SimStateOptions.register_bool_option(v)


# useful sets of options
resilience = {
    BYPASS_UNSUPPORTED_IROP,
    BYPASS_UNSUPPORTED_IREXPR,
    BYPASS_UNSUPPORTED_IRSTMT,
    BYPASS_UNSUPPORTED_IRDIRTY,
    BYPASS_UNSUPPORTED_IRCCALL,
    BYPASS_ERRORED_IRCCALL,
    BYPASS_UNSUPPORTED_SYSCALL,
    BYPASS_ERRORED_IROP,
    BYPASS_VERITESTING_EXCEPTIONS,
    BYPASS_ERRORED_IRSTMT,
}
resilience_options = resilience  # alternate name?
refs = {
    TRACK_REGISTER_ACTIONS,
    TRACK_MEMORY_ACTIONS,
    TRACK_TMP_ACTIONS,
    TRACK_JMP_ACTIONS,
    ACTION_DEPS,
    TRACK_CONSTRAINT_ACTIONS,
}
approximation = {APPROXIMATE_SATISFIABILITY, APPROXIMATE_MEMORY_SIZES, APPROXIMATE_MEMORY_INDICES}
symbolic = {DO_CCALLS, SYMBOLIC, TRACK_CONSTRAINTS, SYMBOLIC_INITIAL_VALUES, COMPOSITE_SOLVER}
simplification = {SIMPLIFY_MEMORY_WRITES, SIMPLIFY_REGISTER_WRITES, SIMPLIFY_MERGED_CONSTRAINTS}
common_options = {
    COW_STATES,
    OPTIMIZE_IR,
    TRACK_MEMORY_MAPPING,
    SUPPORT_FLOATING_POINT,
    EXTENDED_IROP_SUPPORT,
    ALL_FILES_EXIST,
    FILES_HAVE_EOF,
} | simplification
unicorn = {
    UNICORN,
    UNICORN_SYM_REGS_SUPPORT,
    ZERO_FILL_UNCONSTRAINED_REGISTERS,
    UNICORN_HANDLE_CGC_TRANSMIT_SYSCALL,
    UNICORN_TRACK_BBL_ADDRS,
    UNICORN_TRACK_STACK_POINTERS,
}
concrete = {SYNC_CLE_BACKEND_CONCRETE}

modes = {
    "symbolic": common_options | symbolic | {TRACK_CONSTRAINT_ACTIONS},  # | approximation | { VALIDATE_APPROXIMATIONS }
    "symbolic_approximating": common_options | symbolic | approximation | {TRACK_CONSTRAINT_ACTIONS},
    "static": (common_options - simplification)
    | {
        REGION_MAPPING,
        BEST_EFFORT_MEMORY_STORING,
        SYMBOLIC_INITIAL_VALUES,
        DO_CCALLS,
        DO_RET_EMULATION,
        TRUE_RET_EMULATION_GUARD,
        TRACK_CONSTRAINTS,
        ABSTRACT_MEMORY,
        ABSTRACT_SOLVER,
        USE_SIMPLIFIED_CCALLS,
        REVERSE_MEMORY_NAME_MAP,
    },
    "fastpath": (common_options - simplification)
    | (symbolic - {SYMBOLIC, DO_CCALLS})
    | resilience
    | {
        TRACK_OP_ACTIONS,
        BEST_EFFORT_MEMORY_STORING,
        AVOID_MULTIVALUED_READS,
        AVOID_MULTIVALUED_WRITES,
        SYMBOLIC_INITIAL_VALUES,
        DO_RET_EMULATION,
        NO_SYMBOLIC_JUMP_RESOLUTION,
        NO_SYMBOLIC_SYSCALL_RESOLUTION,
        FAST_REGISTERS,
    },
    "tracing": (common_options - simplification - {SUPPORT_FLOATING_POINT, ALL_FILES_EXIST})
    | symbolic
    | resilience
    | (unicorn - {UNICORN_TRACK_STACK_POINTERS})
    | {
        CGC_NO_SYMBOLIC_RECEIVE_LENGTH,
        REPLACEMENT_SOLVER,
        EXCEPTION_HANDLING,
        ZERO_FILL_UNCONSTRAINED_MEMORY,
        PRODUCE_ZERODIV_SUCCESSORS,
        ALLOW_SEND_FAILURES,
        SYMBOLIC_MEMORY_NO_SINGLEVALUE_OPTIMIZATIONS,
        MEMORY_FIND_STRICT_SIZE_LIMIT,
        CPUID_SYMBOLIC,
    },
}

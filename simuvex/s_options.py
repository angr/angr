# This module contains the analysis options

# These options cause SimuVEX to set breakpoints in various places.
BREAK_SIRSB_START = "BREAK_SIRSB_START"
BREAK_SIRSB_END = "BREAK_SIRSB_END"
BREAK_SIRSTMT_START = "BREAK_SIRSTMT_START"
BREAK_SIRSTMT_END = "BREAK_SIRSTMT_END"

# This makes SimIRSBs do a fastpath analysis, only recovering direct jumps.
SIMIRSB_FASTPATH = "SIMIRSB_FASTPATH"

# This option controls whether register puts are carried out by the analysis.
# Without this, put statements are still analyzed, but the state is not updated.
DO_PUTS = "DO_PUTS"

# This option controls whether register puts are carried out by the analysis.
# Without this, put statements are still analyzed, but the state is not updated.
#DO_GETS = "#DO_GETS"

# This option controls whether memory stores are carried out by the analysis
# Without this, store statements are still analyzed, but the state is not updated.
DO_STORES = "DO_STORES"

# This option controls whether memory loads are carried out by the analysis
# Without this, load statements are still analyzed, but the state is not updated.
DO_LOADS = "DO_LOADS"

# This option controls whether or not constraints are tracked in the analysis.
TRACK_CONSTRAINTS = "TRACK_CONSTRAINTS"

# This option causes constraints to be flushed at the beginning of every instruction.
INSTRUCTION_SCOPE_CONSTRAINTS = "INSTRUCTION_SCOPE_CONSTRAINTS"
BLOCK_SCOPE_CONSTRAINTS = "BLOCK_SCOPE_CONSTRAINTS"

# This option controls whether or not various entities (IRExpr constants, reads, writes, etc) get simplified automatically
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

# This option controls whether Unop, BinOp, TriOp, and QOp expressions are executed by the analysis.
# Without this, the statements are still analyzed, but the result remains a purely symbolic value.
#DO_OPS = "#DO_OPS"

# This option controls whether the helper functions are actually executed for CCALL expressions.
# Without this, the arguments are parsed, but the calls aren't executed, and an unconstrained symbolic
# variable is returned, instead.
DO_CCALLS = "DO_CCALLS"

# This option controls whether or not emulated exits and coderefs are added from a call instruction to its ret site.
DO_RET_EMULATION = "DO_RET_EMULATION"

# This option causes the analysis to immediately concretize any symbol that it comes across
CONCRETIZE = "CONCRETIZE"

# This option causes the analysis to stop executing a basic block when the first taken exit is encountered.
SINGLE_EXIT = "SINGLE_EXIT"

# The absense of this option causes the analysis to avoid reasoning about most symbolic values.
SYMBOLIC = "SYMBOLIC"

# this causes SimuVEX to use SimAbstractMemory for the memory region
ABSTRACT_MEMORY = "ABSTRACT_MEMORY"

# This disallows *any* reasoning about symbolic values.
CONCRETE_STRICT = "CONCRETE_STRICT"

# This controls whether the temps are treated as symbolic values (for easier debugging) or just written as the z3 values
SYMBOLIC_TEMPS = "SYMBOLIC_TEMPS"

# This option causes all expression values to be checked against currently mapped memory to identify
# expressions that point to it.
MEMORY_MAPPED_REFS = "MEMORY_MAPPED_REFS"

# This option enables the recording of SimMemWrite and SimMemRead refs.
MEMORY_REFS = "MEMORY_REFS"

# This option enables the recording of SimRegWrite and SimRegRead refs
REGISTER_REFS = "REGISTER_REFS"

# This option enables the recording of SimTmpWrite and SimTmpRead refs
TMP_REFS = "TMP_REFS"

# This option enables the recording of SimCodeRef refs
CODE_REFS = "CODE_REFS"

# this makes s_run() copy states
COW_STATES = "COW_STATES"

# this replaces calls with an unconstraining of the return register
CALLLESS = "CALLLESS"

# these enables indepent constraint set optimizations. The first is a master toggle, and the second controls
# splitting constraint sets during simplification
COMPOSITE_SOLVER = "COMPOSITE_SOLVER"
ABSTRACT_SOLVER = "ABSTRACT_SOLVER"
PARALLEL_SOLVES = "PARALLEL_SOLVES"

# This controls whether state executes in native or python mode
NATIVE_EXECUTION = "NATIVE_EXECUTION"

# This makes simuvex downsize solvers wherever reasonable.
DOWNSIZE_Z3 = "DOWNSIZE_Z3"

# Concretize certain registers if they're unique
CONCRETIZE_UNIQUE_REGS = "CONCRETIZE_UNIQUE_REGS"

# Resilience options
BYPASS_UNSUPPORTED_IROP = "BYPASS_UNSUPPORTED_IROP"
BYPASS_UNSUPPORTED_IREXPR = "BYPASS_UNSUPPORTED_IREXPR"
BYPASS_UNSUPPORTED_IRSTMT = "BYPASS_UNSUPPORTED_IRSTMT"
BYPASS_UNSUPPORTED_IRDIRTY = "BYPASS_UNSUPPORTED_IRDIRTY"
BYPASS_UNSUPPORTED_IRCCALL = "BYPASS_UNSUPPORTED_IRCCALL"
BYPASS_ERRORED_IRCCALL = "BYPASS_ERRORED_IRCCALL"
BYPASS_UNSUPPORTED_SYSCALL = "BYPASS_UNSUPPORTED_SYSCALL"

# Default options for various modes
default_options = { }
resilience_options = { BYPASS_UNSUPPORTED_IROP, BYPASS_UNSUPPORTED_IREXPR, BYPASS_UNSUPPORTED_IRSTMT, BYPASS_UNSUPPORTED_IRDIRTY, BYPASS_UNSUPPORTED_IRCCALL, BYPASS_ERRORED_IRCCALL, BYPASS_UNSUPPORTED_SYSCALL }
refs = { REGISTER_REFS, MEMORY_REFS, TMP_REFS, CODE_REFS }
symbolic = { DO_CCALLS, SYMBOLIC, TRACK_CONSTRAINTS }
fastpath = { SIMIRSB_FASTPATH, DO_RET_EMULATION }

simplification = { SIMPLIFY_MEMORY_WRITES, SIMPLIFY_EXIT_STATE, SIMPLIFY_EXIT_GUARD, SIMPLIFY_REGISTER_WRITES }

common_options = { DO_PUTS, DO_LOADS, COW_STATES, DO_STORES } | simplification
default_options['symbolic'] = common_options | refs | symbolic #| { COMPOSITE_SOLVER }
default_options['symbolic_norefs'] = common_options | symbolic
default_options['concrete'] = common_options | refs | { DO_CCALLS, MEMORY_MAPPED_REFS, CONCRETE_STRICT, DO_RET_EMULATION }
default_options['static'] = common_options | refs | { MEMORY_MAPPED_REFS, DO_RET_EMULATION, BLOCK_SCOPE_CONSTRAINTS, TRACK_CONSTRAINTS, ABSTRACT_MEMORY }
default_options['fastpath'] = fastpath

# This module contains the analysis options

def flag_counter():
    a = 1
    yield a
    while True:
        a = a * 2
        yield a

c = flag_counter()

# These options cause SimuVEX to set breakpoints in various places.
BREAK_SIRSB_START = c.next()
BREAK_SIRSB_END = c.next()
BREAK_SIRSTMT_START = c.next()
BREAK_SIRSTMT_END = c.next()

# This option controls whether register puts are carried out by the analysis.
# Without this, put statements are still analyzed, but the state is not updated.
DO_PUTS = c.next()

# This option controls whether register puts are carried out by the analysis.
# Without this, put statements are still analyzed, but the state is not updated.
#DO_GETS = c.next()

# This option controls whether memory stores are carried out by the analysis
# Without this, store statements are still analyzed, but the state is not updated.
DO_STORES = c.next()

# This option controls whether memory loads are carried out by the analysis
# Without this, load statements are still analyzed, but the state is not updated.
DO_LOADS = c.next()

# This option controls whether or not constraints are tracked in the analysis.
TRACK_CONSTRAINTS = c.next()

# This option controls whether or not constant SimIRExpr.expr expressions are automatically simplified
SIMPLIFY_CONSTANTS = c.next()

# This option controls whether Unop, BinOp, TriOp, and QOp expressions are executed by the analysis.
# Without this, the statements are still analyzed, but the result remains a purely symbolic value.
#DO_OPS = c.next()

# This option controls whether the helper functions are actually executed for CCALL expressions.
# Without this, the arguments are parsed, but the calls aren't executed.
#DO_CCALLS = c.next()

# This option controls whether or not emulated exits and coderefs are added from a call instruction to its ret site.
DO_RET_EMULATION = c.next()

# This option causes the analysis to immediately concretize any symbol that it comes across
CONCRETIZE = c.next()

# This option causes the analysis to stop executing a basic block when the first taken exit is encountered.
SINGLE_EXIT = c.next()

# The absense of this option causes the analysis to avoid reasoning about most symbolic values.
SYMBOLIC = c.next()

# This disallows *any* reasoning about symbolic values.
CONCRETE_STRICT = c.next()

# This controls whether the temps are treated as symbolic values (for easier debugging) or just written as the z3 values
SYMBOLIC_TEMPS = c.next()

# This option causes all expression values to be checked against currently mapped memory to identify
# expressions that point to it.
MEMORY_MAPPED_REFS = c.next()

# This option enables the recording of SimMemWrite and SimMemRead refs.
MEMORY_REFS = c.next()

# This option enables the recording of SimRegWrite and SimRegRead refs
REGISTER_REFS = c.next()

# This option enables the recording of SimTmpWrite and SimTmpRead refs
TMP_REFS = c.next()

# This option enables the recording of SimCodeRef refs
CODE_REFS = c.next()

# this makes s_run() copy states
COW_STATES = c.next()

# this replaces calls with an unconstraining of the return register
CALLLESS = c.next()

# Default options for various modes
default_options = { }
common_options = { DO_PUTS, DO_LOADS, SIMPLIFY_CONSTANTS, COW_STATES }
refs = { REGISTER_REFS, MEMORY_REFS, TMP_REFS, CODE_REFS }

default_options['symbolic'] = common_options | refs | { DO_STORES, SYMBOLIC, TRACK_CONSTRAINTS }
default_options['symbolic_norefs'] = common_options | { DO_STORES, SYMBOLIC, TRACK_CONSTRAINTS }
default_options['concrete'] = common_options | refs | { DO_STORES, MEMORY_MAPPED_REFS, SINGLE_EXIT, CONCRETE_STRICT, DO_RET_EMULATION }
default_options['static'] = common_options | refs | { MEMORY_MAPPED_REFS, DO_STORES, DO_RET_EMULATION, TRACK_CONSTRAINTS }

# This module contains the analysis options

def flag_counter():
	a = 1
	yield a
	while True:
		a = a * 2
		yield a

c = flag_counter()

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

# This option causes the analysis to identify the exit that would be actually taken for a given IRSB.
# With this exit present, only the taken exit is returned by exits().
# This option implies the absense of DO_RET_EMULATION.
SINGLE_EXIT = c.next()

# The absense of this option causes the analysis to avoid reasoning about symbolic values at all.
SYMBOLIC = c.next()

# This option causes all expression values to be checked against currently mapped memory to identify
# expressions that point to it.
MEMORY_MAPPED_REFS = c.next()

# This option enables the recording of SimMemWrite and SimMemRead refs.
MEMORY_REFS = c.next()

# This option enables the recording of SimRegWrite and SimRegRead refs
REGISTER_REFS = c.next()

# This option enables the recording of SimTmpWrite and SimTmpRead refs
TMP_REFS = c.next()

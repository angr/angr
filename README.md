# simuvex

SimuVEX is a simulation engine for VEX IR. Given VEX IRSBs and an initial state (memory and registers), it can carry out static, dynamic, or symbolic analyses.

# Requirements

SimuVEX has the following requirements:

- pyvex (https://github.com/zardus/pyvex)
- cooldict (https://github.com/zardus/cooldict)
- symexec (https://git.seclab.cs.ucsb.edu/gitlab/yans/symexec)

# Usage

There are several main categories of 'stuff' in SimuVEX:

## Symbolic/concrete values

**SimValue**

SimValue represents a symbolic or concrete value in SimuVEX. A symbolic value consists of a symexec/z3 expression and a set of constraints. A concrete value is just the expression. For example:

	import symexec
	import simuvex

	v = simuvex.SimValue(symexec.BitVecVal(10, 32))
	v.is_symbolic() # Returns: False
	v.size() # Returns: 32
	v.any() # Returns: 10

	x = symexec.BitVec("x", 32)
	v = simuvex.SimValue(x, [ x > 100 ])
	v.is_symbolic() # Returns: True
	v.satisfiable() # Returns: True
	v.size() # Returns: 32
	v.any() # Returns: 101
	v.any_n(10) # Returns: (101, 102, 103, 104, 105, 106, 107, 108, 109, 110)
	v.is_solution(22) # Returns: False

## Analysis State

SimuVEX ingests an initial state for an analysis and outputs a resulting state. The following classes are used in this process:

**SimMemory**

SimMemory represents the (symbolic or concrete) memory space of a program. There is one SimMemory for memory and, since VEX represents the register file as a memory region, one for registers. SimMemory SimMemory supports the following interfaces:

	import symexec
	import simuvex

	#
	# example with concrete addresses
	#

	initial_memory = { 0: 0x41, 1: 0x41, 2: 0x41, 3: 0x41 }
	mem = simuvex.SimMemory(backer=initial_memory)

	addr = simuvex.SimValue(symexec.BitVecVal(0, 64))
	mem.load(addr, 4) # Returns: a z3 BitVec representing 0x41414141

	data = symexec.BitVecVal(0xffff, 16)
	mem.store(addr, data)
	mem.load(addr, 4) # Returns: a z3 BitVec representing 0xffff4141

	#
	# example with symbolic addresses
	#

	mem = simuvex.SimMemory()
	x = symexec.BitVec("x", 32)
	addr = simuvex.SimValue(x, [ x > 100 ])
	data = symexec.BitVecVal(0xffff, 16)

	new_constraint = mem.store(addr, data) # Returns: [ x == 101 ]
	addr.push_constraints(**new_constraint)
	mem.load(addr, 4) # Returns: a z3 BitVec representing 0xffffXXXX with XXXX being two symbolic bytes

	mem_copy = mem.copy() # a fast copy of memory, using a shared backing dictionary with the original.
	                      # Modifications to the copy and the original don't affect each other.

**SimArch**

SimArch tracks architecture-dependent things. This includes the VEX index of the instruction and stack pointers, the bitness of the architecture, the VexArch of the architecture, the maximum instruction size, and function emulation code (ie, emulated returns from a call instruction).

**SimState**

SimState combines the memory state, register state, temp state, and symbolic constraints of an analysis. A SimState is copy-on-write. That is, it can be branched off into future states.

	import simuvex
	import symexec

	x = symexec.BitVec("x", 32)
	s = simuvex.SimState()
	s.add_constraints(x > 100)

	s.constraints_after() # all of the added constriants. In this case, [ x > 100 ]
	s_before = s.copy_before() # this is the state before constraints were added
	s2 = s.copy_after() # this is a new state, with copied memory and registers and constraints

## Main Analysis

Analyses in SimuVEX work by translating VEX IR into symbolic statements. Understanding VEX IR is highly recommended in order to understand this part.

**SimIRExpr**

TODO

**SimIRStmt**

TODO

**SimIRSB**

TODO

**SimExit**

TODO

**SimRef**

TODO

## Slicing it up!

TODO

**SimPath**

TODO

**SimSlice**

TODO

# Supporting a new architecture

These are the steps required to support a new VEX arch:

1. Implement the ccalls that VEX uses for that architecture (for example, the condition flag crap). These are located in s\_ccall.py.
2. Implement a SimARCH class for it in s\_arch.py. This is for stuff like return emulation, and the bit width of the architecture.

# Next steps

# Bugs

- None! (haha)

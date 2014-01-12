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

SimuVEX provides an abstraction for values (whether symbolic or concrete) in the form of SimValue. A symbolic SimValue value consists of a symexec/z3 expression and a set of constraints. A concrete value is just the expression. The interface is the same for both. For example:

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

SimuVEX SimRuns (explained later) ingest an initial state for an analysis and output resulting states. The following classes comprise SimuVEX's states:

**SimMemory**

SimMemory represents the (symbolic or concrete) memory space of a program. Normally, there is one SimMemory instance for memory and, since VEX represents the register file as a memory region, one for registers. SimMemory SimMemory supports the following interfaces:

	#
	# example with concrete addresses
	#

	initial_memory = { 0: 0x41, 1: 0x41, 2: 0x41, 3: 0x41 }
	mem = simuvex.SimMemory(backer=initial_memory)

	mem.load(0, 4) # Returns: a z3 BitVec representing 0x41414141

	data = symexec.BitVecVal(0xffff, 16)
	mem.store(0, data)
	mem.load(0, 4) # Returns: a z3 BitVec representing 0xffff4141

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

SimArch tracks architecture-dependent information. This includes the VEX offsets of various registers, the bitness of the architecture, the VexArch of the architecture, the maximum instruction size, and function emulation code (ie, emulated returns from a call instruction).

**SimStatePlugin**

Certain additional information needs to be stored in the state. For analysis of software on POSIX systems, for example, the state of the system (open files, etc) must be tracked. This is done with SimStatePlugins.

**SimState**

SimState combines the memory state, register state, temp state, any state plugins, and symbolic constraints of an analysis. A SimState is copy-on-write. That is, it can be branched into many independent states. SimState also exposes an interface for performing common operations such as viewing and modifying the stack.

	x = symexec.BitVec("x", 32)
	s = simuvex.SimState()
	s.add_constraints(x > 100)
	s.add_branch_constraints(x == 5) # pretend we're currently evaluating something like "if (x==5)"

	#
	# States can be branched.
	#

	s.constraints_after() # all of the added constriants. In this case, [ x > 100 ]
	s_before = s.copy_before() # this is the state before constraints were added
	s2 = s.copy_after() # this is a new state, with copied memory and registers and constraints. The x==5 path is taken.
	s3 = s.copy_avoid() # this is a new state, with the x==5 path *not* taken (that is, x != 5)

	#
	# The state provides an interface to registers, memory, the stack, etc.
	#

	sp = s.reg_value(s.arch.sp_offset) # get the SimValue of the stack pointer
	ip = s.reg_value(s.arch.ip_offset) # get the SimValue of the instruction pointer
	some_code = s.mem_value(ip, 4) # read the next 4 bytes from the instruction pointer
	stack_value = s.stack_pop() # do a pop, updating the stack pointer and returning what was on the stack
	s.stack_push(stack_value) # do a push
	stack_value = s.stacK_read(-4) # read the value stored on the stack

	#
	# The state provides plugins.
	#

	input = s.get_plugin('posix').read(0, 10) # read 10 (possibly symbolic) bytes from standard input
	s.get_plugin('posix').write(1, input, input.size()) # write 10 bytes to standard output

	fd = s.get_plugin('posix').open('some_file', 'r') # open a file for reading, keeping it symbolic if it doesn't exist
	buff = s.get_plugin('posix').read(fd, 8) # read 8 (possibly symbolic) bytes from it

## Analysis Interface

**SimRef**

A SimRef represents a reference (read, write, or mention) of a memory, register, or temp.

	TODO: provide example

**SimExit**

A SimExit is a combination of an address, representing the target of a jump, and a SimState. It has the following interface:

	some_state = SimState()
	some_exit = SimExit(addr=0x800400, state=some_state)
	some_exit.concretize() # returns the concrete value of the jump target, in this case 0x800400

	x = symexec.BitVec("x", 32)
	some_state.add_constraints(x > 0x800000)
	some_state.add_constraints(x < 0x800100)
	some_state.add_constraints(x % 20 == 0)
	some_state.add_constraints(x % 40 != 0)
	some_exit = SimExit(expr=x, state=some_state)
	some_exit.concretize() # throws an exception because there are multiple possible targets
	some_exit.concretize_n(10) # returns a tuple with up to 10 possible targets: (0x800020, 0x800060)

**SimRun**

SimuVEX organizes its analyses into SimRuns. A SimRun is some operation that consumes an input state and produces several exit states. Currently, this includes binary basic blocks, paths through a program, and abstract functions. The interface is as follows:

	class SomeImplementedAnalysis(SimRun):
		...

	input_state = SimState(...)
	s = SomeImplementedAnalysis(input_state)
	s.exits() # outputs SimExits representing the possible exits from the state

**Analysis Options**

Analysis options control the way analyses are performed. They can be set inidividually, or chosen from pre-designed sets:

	# do a symbolic analysis with memory loads, but not memory stores or other options
	options = (simuvex.o.SYMBOLIC, simuvex.o.DO_LOADS)
	s = SomeImplementedAnalysis(input_state, options=options)

	# do a standard symbolic analysis
	s = SomeImplementedAnalysis(input_state, mode="symbolic")

	# do a dynamic analysis (everything concrete, always returning a single exit to take)
	s = SomeImplementedAnalysis(input_state, mode="concrete")

The full list of options and their descriptions can be found in s\_options.py

## Binary Analysis

Binary analysis in SimuVEX works by translating VEX IR into symbolic statements. Understanding VEX IR is highly recommended in order to understand this functionality.

**SimIRExpr**

A SimIRExpr is a symbolic model of a specific instance of a VEX IRExpr, analyzing what the IRExpr reads or calculates.

**SimIRStmt**

A SimIRStmt is a symbolic model of a specific instance of a VEX IRStmt. It analyzes any expressions on which the statement depends, then carries out necessary modifications to a SimState.

**SimIRSB**

A SimIRSB is a SimRun analysis on a VEX IRSB. It takes a VEX block as input.

	vex_block = pyvex.IRSB(...)
	sirsb = SimIRSB(input_state, vex_block)
	sirsb.refs() # the references made by this block
	sirsb.exits() # the exits from this block

## Slicing it up!

It is sometimes useful to force the analysis to proceed through a certain set of instructions. SimPath and SimSlice are provided for this purpose.

**SimPath**

SimPath is a SimRun representing the concatenation of several SimRuns, such as IRSBs. Paths support being split into several independent copies.

	path = SimPath(initial_state)
	path.add_irsb(vex_block)
	path.add_irsb(vex_block2)
	path.exits() # the exits from the path
	path.refs() # the references made by the path

	split_path = path.copy()

**SimSlice**

Analysis of a provided set of instructions might actually proceed down those instructions in different ways. An example of this is a conditional jumps that points to the instruction after it, so that a symbolic analysis through those instructions could either take the state where the condition is true or that where it is false. For this reason, SimSlice is provided as a way of tracking multiple SimPaths over a number of instructions:

	TODO: example

# Supporting a new architecture

These are the steps required to support a new VEX arch:

1. Implement the ccalls that VEX uses for that architecture (for example, the condition flag crap). These are located in s\_ccall.py.
2. Implement a SimARCH class for it in s\_arch.py. This is for stuff like return emulation, and the bit width of the architecture.

## Abstract functions

**SimProcedure**

TODO

# Next steps

- Test cases
- Creation of more abstract functions
- State merging
 - could be done by creating a new symbolic value ("which\_state") and simply placing If(which\_state, value\_b, value\_a) for each value to merge states a and b. State plugins (file descriptors and the like) would be slightly tricky.

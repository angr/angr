#!/usr/bin/env python

import copy

import symexec
import s_memory
import s_arch
from .s_value import SimValue

import logging
l = logging.getLogger("s_state")

class SimState:
	def __init__(self, temps=None, registers=None, memory=None, old_constraints=None, state_id="", arch="AMD64", block_path=None, memory_backer=None):
		# the architecture is used for function simulations (autorets) and the bitness
		self.arch = s_arch.Architectures[arch] if isinstance(arch, str) else arch

		# VEX temps are temporary variables local to an IRSB
		self.temps = temps if temps is not None else { }

		# VEX treats both memory and registers as memory regions
		if memory:
			self.memory = memory
		else:
			if memory_backer is None: memory_backer = { }
			vectorized_memory = s_memory.Vectorizer(memory_backer)
			self.memory = s_memory.SimMemory(vectorized_memory, memory_id="mem", bits=self.arch.bits)

		if registers:
			self.registers = registers
		else:
			self.registers = s_memory.SimMemory({ }, memory_id="reg", bits=self.arch.bits)

		# let's keep track of the old and new constraints
		self.old_constraints = old_constraints if old_constraints else [ ]
		self.new_constraints = [ ]
		self.branch_constraints = [ ]

		self.block_path = block_path if block_path else [ ]
		self.id = state_id

		try:
			self.id = "0x%x" % int(str(self.id))
		except ValueError:
			pass

	def tmp_value(self, tmp, when="after"):
		if when == "after":
			c = self.constraints_after()
		elif when == "before":
			c = self.constraints_before()
		elif when == "avoid":
			c = self.constraints_avoid()

		return SimValue(self.temps[tmp], c)

	def simplify(self):
		if len(self.old_constraints) > 0:
			self.old_constraints = [ symexec.simplify(symexec.And(*self.old_constraints)) ]

		if len(self.new_constraints) > 0:
			self.new_constraints = [ symexec.simplify(symexec.And(*self.new_constraints)) ]

		if len(self.branch_constraints) > 0:
			self.branch_constraints = [ symexec.simplify(symexec.And(*self.branch_constraints)) ]

	def constraints_after(self):
		return self.old_constraints + self.new_constraints + self.branch_constraints

	def constraints_before(self):
		return copy.copy(self.old_constraints)

	def constraints_avoid(self):
		# if there are no branch constraints, we can't avoid
		if len(self.branch_constraints) == 0:
			return self.old_constraints + [ symexec.BitVecVal(1, 1) == 0 ]
		else:
			return self.old_constraints + [ symexec.Not(symexec.And(*self.branch_constraints)) ]

	def add_constraints(self, *args):
		self.new_constraints.extend(args)

	def add_branch_constraints(self, *args):
		self.branch_constraints.extend(args)

	def clear_constraints(self):
		self.old_constraints = [ ]
		self.new_constraints = [ ]
		self.branch_constraints = [ ]


	####################################
	### State progression operations ###
	####################################

	# Applies new constraints to the state so that a branch is avoided.
	def inplace_avoid(self):
		self.old_constraints = self.constraints_avoid()
		self.new_constraints = [ ]
		self.branch_constraints = [ ]

	# Applies new constraints to the state so that a branch (if any) is taken
	def inplace_after(self):
		self.old_constraints = self.constraints_after()
		self.new_constraints = [ ]
		self.branch_constraints = [ ]

	##################################
	### State branching operations ###
	##################################

	# Copies a state without its constraints
	def copy_unconstrained(self):
		c_temps = copy.copy(self.temps)
		c_mem = self.memory.copy()
		c_registers = self.registers.copy()
		c_constraints = [ ]
		c_id = self.id
		c_arch = self.arch
		c_bs = copy.copy(self.block_path)

		return SimState(c_temps, c_registers, c_mem, c_constraints, c_id, c_arch, c_bs)

	# Copies a state so that a branch (if any) is taken
	def copy_after(self):
		c = self.copy_unconstrained()
		c.old_constraints = self.constraints_after()
		return c

	# Creates a copy of the state, discarding added constraints
	def copy_before(self):
		c = self.copy_unconstrained()
		c.old_constraints = self.constraints_before()

		return c

	# Copies a state so that a branch is avoided
	def copy_avoid(self):
		c = self.copy_unconstrained()
		c.old_constraints = self.constraints_avoid()
		return c

	# Copies the state, with all the new and branch constraints un-applied but present
	def copy_exact(self):
		c = self.copy_before()
		c.new_constraints = copy.copy(self.new_constraints)
		c.branch_constraints = copy.copy(self.branch_constraints)

	###############################
	### Stack operation helpers ###
	###############################

	# Push to the stack, writing the thing to memory and adjusting the stack pointer.
	def stack_push(self, thing):
		return self.arch.stack_push(self, thing)

	# Pop from the stack, adjusting the stack pointer and returning the popped thing.
	def stack_pop(self):
		return self.arch.stack_pop(self)

	# Read some number of bytes from the stack at the provided offset.
	def stack_read(self, offset, length):
		return self.arch.stack_read(offset, length)

#!/usr/bin/env python

''' This file contains support for SimSlice. '''

import logging
l = logging.getLogger("s_slice")

import pyvex
from .s_irsb import SimIRSB
from .s_exception import SimError
from .s_exit import SimExit

class SimSliceError(SimError):
	pass

class SimSlice:
	# SimSlice adds support for program slicing. It accepts a set of addresses and analyzes a slice containing those addresses.
	# Currently, code changes during the runtime of the slice are *not* supported.
	def __init__(self, initial_state, addresses, mode):
		self.data_reads = [ ]
		self.data_writes = [ ]
		self.memory_refs = [ ]
		self.code_refs = [ ]
		self.sim_blocks = [ ]
		self.mode = mode

		# prepare the states
		self.initial_state = initial_state
		initial_exit = SimExit(addr = addresses[0], addr_state = initial_state)
		
		self.final_exits = [ initial_exit ]
		self.blockstacks = [ [ ] ]
		self.add_addresses(addresses)

	def add_addresses(self, addresses):
		max_inst_bytes = self.initial_state.arch.max_inst_bytes

		l.debug("Adding %d addresses to slice.", len(addresses))

		# make a one-instruction IRSB at the addresses
		instructions = [ ]
		for addr in addresses:
			irsb = pyvex.IRSB(bytes=self.initial_state.memory.read_from(addr, max_inst_bytes, constraints=[ ]), num_inst = 1, mem_addr=addr)
			#sirsb = SimIRSB(irsb, initial_state, mode=mode)
			first_imark = [ s for s in irsb.statements() if type(s) == pyvex.IRStmt.IMark ][0]

			l.debug("Instruction of size %d at 0x%x", first_imark.len, first_imark.addr)
			instructions.append((irsb, first_imark))

		l.debug("Sanity check: %d IMarks", len(instructions))

		# add the parts of the slice
		start_addr = None
		next_addr = None
		num_inst = 0
		num_bytes = 0
		for _, imark in instructions:
			l.debug("Looking at IMark with addr 0x%x and len %d", imark.addr, imark.len)
			if start_addr is None:
				l.debug("... first imark")
				start_addr = imark.addr
				next_addr = imark.addr
				num_inst = 0
				num_bytes = 0

			if next_addr != imark.addr:
				# we're done with this part of the slice; add it
				l.debug("... adding block of %d instructions and %d bytes starting at 0x%x", num_inst, num_bytes, start_addr)
				self.add_block(start_addr, num_inst, num_bytes)

				start_addr = imark.addr
				next_addr = imark.addr
				num_bytes = 0
				num_inst = 0

			next_addr += imark.len
			num_bytes += imark.len
			num_inst += 1

		l.debug("Adding final block of %d instructions and %d bytes starting at 0x%x", num_inst, num_bytes, start_addr)
		self.add_block(start_addr, num_inst, num_bytes)


	def add_block(self, addr, num_inst, num_bytes):
		# check current exit states for one that points to addr
		# if it doesn't exist, debug and just take the last one for now
		# replace the current exits with the new last one's exits

		reachable_exits = [ (e,s) for e,s in zip(self.final_exits, self.blockstacks) if e.reachable() ]
		l.debug("%d reachable exits", len(reachable_exits))
		if len(reachable_exits) == 0:
			raise SimSliceError("No sat path when starting block 0x%x while building slice.", addr)

		feasible_states = [ ]
		unfeasible_states = [ ]
		for e,s in reachable_exits:
			if e.simvalue.is_solution(addr):
				feasible_states.append((e.state, s))
			else:
				unfeasible_states.append((e.state, s))

		l.debug("%d feasible and %d unfeasible exits", len(feasible_states), len(unfeasible_states))

		# if there are no feasible solutions (which can happen if we're skipping instructions), use the unfeasible states
		if len(feasible_states) == 0:
			feasible_states = unfeasible_states

		self.final_exits = [ ]
		self.blockstacks = [ ]
		for state, stack in feasible_states:
			try:
				irsb = pyvex.IRSB(bytes=state.memory.read_from(addr, num_bytes, constraints=[ ]), num_inst = num_inst, mem_addr=addr)
				sirsb = SimIRSB(irsb, state, mode=self.mode)
				stack.append(sirsb)

				# TODO: track the data refs for the different possibilities
				# TODO: fix up the instruction pointer to the next location if it's known.
				new_exits = sirsb.exits()
				for e in new_exits:
					self.final_exits.append(e)
					self.blockstacks.append(stack)
			except SimError:
				l.warning("SimError caught while adding a state to a slice.", exc_info=True)

		l.debug("%d exits", len(self.final_exits))

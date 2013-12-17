#!/usr/bin/env python

import logging
l = logging.getLogger("s_slice")

import pyvex
import symexec
from .s_irsb import SimIRSB
from .s_exception import SimError
from .s_exit import SimExit

class SimSliceError(SimError):
	pass

class SimSlice:
	def __init__(self, initial_state, addresses, mode):
		max_inst_bytes = initial_state.arch.max_inst_bytes
		self.data_reads = [ ]
		self.data_writes = [ ]
		self.memory_refs = [ ]
		self.code_refs = [ ]
		self.mode = mode;

		# make a one-instruction IRSB at the addresses
		instructions = [ ]
		for addr in addresses:
			irsb = pyvex.IRSB(bytes=initial_state.memory[addr:addr + max_inst_bytes], max_inst = 1)
			#sirsb = SimIRSB(irsb, initial_state, mode=mode)
			first_imark = [ s for s in irsb.statements() if type(s) == pyvex.IMark ][0]

			instructions.append(irsb, first_imark)

		# prepare the states
		self.initial_state = initial_state
		initial_exit = [ SimExit(empty = True) ]
		initial_exit.state = initial_state.copy_after()
		initial_exit.s_target = symexec.BitVecVal(addresses[0], initial_state.arch.bits)
		initial_state.jumpkind = "Ijk_Boring"
		
		self.final_exits = [ initial_exit ]

		# add the parts of the slice
		start_addr = 0
		next_addr = None
		num_inst = 0
		num_bytes = 0
		for imark,_ in instructions:
			if next_addr != imark.addr:
				# we're done with our slice; add it
				self.add_to_slice(start_addr, next_addr, num_inst, num_bytes)
			next_addr += imark.addr
			num_bytes += imark.len
			num_inst += 1


	def add_to_slice(self, addr, num_inst, num_bytes):
		# check current exit states for one that points to addr
		# if it doesn't exist, debug and just take the last one for now
		# replace the current exits with the new last one's exits

		reachable_exits = [ exit for exit in self.final_exits if exit.reachable() ]
		l.debug("%d reachable exits", len(reachable_exits))

		feasible_states = [ ]
		unfeasible_states = [ ]
		for exit in reachable_exits:
			if exit.simvalue.is_solution(addr):
				feasible_states.append(exit.state)
			else:
				unfeasible_states.append(exit.state)

		# if there are no feasible solutions (which can happen if we're skipping instructions), use the unfeasible states
		if len(feasible_states) == 0: feasible_states = unfeasible_states

		self.final_exits = [ ]
		for state in feasible_states:
			try:
				irsb = pyvex.IRSB(bytes=state.memory[addr:addr + num_bytes], max_inst = num_inst)
				sirsb = SimIRSB(irsb, state, mode=self.mode)
				# TODO: track the data refs for the different possibilities
				# TODO: fix up the instruction pointer to the next location if it's known.
				self.final_exits.extend(sirsb.exits())
			except SimError:
				l.warning("SimError caught while adding a state to a slice.", exc_info=True)

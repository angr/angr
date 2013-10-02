#!/usr/bin/env python
'''This module handles constraint generation.'''

import os
import z3
import s_irsb
from s_value import ConcretizingException

import logging
l = logging.getLogger("symbolic")
l.setLevel(logging.DEBUG)

try:
	z3_path = os.environ["Z3PATH"]
except Exception:
	z3_path = "/opt/python/lib/"
z3.init(z3_path + "libz3.so")

def translate_bytes(base, bytes, entry, initial_registers = None, initial_memory = None, initial_constraints = None, bits=64):
	l.debug("Translating %d bytes, starting from %x" % (len(bytes), entry))
	remaining_exits = [ ]
	visited_starts = set()
	blocks = [ ]
	unsat_exits = [ ]
	exits_out = [ ]

	memory = initial_memory if initial_memory else { }
	registers = initial_registers if initial_registers else { }
	constraints = initial_constraints if initial_constraints else [ ]

	# take an initial exit and go
	s_entry = z3.BitVecVal(entry, bits)
	remaining_exits.append(s_irsb.SymbolicExit(s_entry, registers, memory, constraints))
	while remaining_exits:
		current_exit = remaining_exits[0]
		remaining_exits = remaining_exits[1:]

		# If we are calling, add the next instruction as another exit
		# TODO: actually handle this properly (taking into account the analysis of the function)
		if current_exit.after_ret is not None:
			cr_start = z3.BitVecVal(current_exit.after_ret, bits)
			cr_reg = current_exit.registers
			cr_mem = current_exit.memory
			cr_con = current_exit.constraints
			remaining_exits.append(s_irsb.SymbolicExit(cr_start, cr_reg, cr_mem, cr_con))

		# get the concrete value
		# TODO: deal with possibility of multiple exits
		l.debug("Concretizing start value...")
		try:
			concrete_start = current_exit.concretize()
		except ConcretizingException:
			l.warning("UNSAT exit condition")
			unsat_exits.append(current_exit)
			continue

		l.debug("... concretized start: %x" % concrete_start)
		byte_start = concrete_start - base
		if byte_start < 0 or byte_start >= len(bytes):
			l.info("Exit jumps to %x, outside of the provided bytes." % concrete_start)
			exits_out.append(current_exit)
			continue

		if concrete_start not in visited_starts:
			l.debug("... processing block")
			visited_starts.add(concrete_start)
                        sirsb = s_irsb.SymbolicIRSB(base=base, bytes=bytes, byte_start=byte_start, constraints=current_exit.constraints, memory=current_exit.memory)
			exits = sirsb.exits()
			remaining_exits.extend(exits)
			l.debug("Got %d exits" % len(exits))

			blocks.append((concrete_start - base, sirsb))

	return blocks, exits_out, unsat_exits

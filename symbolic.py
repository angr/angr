#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import idalink
import symbolic_irsb
import symbolic_value

import logging
l = logging.getLogger("symbolic")
l.setLevel(logging.DEBUG)

z3.init("/opt/python/lib/libz3.so")

def translate_bytes(base, bytes, entry, bits=64):
	l.debug("Translating %d bytes, starting from %x" % (len(bytes), entry))
	remaining_exits = [ ]
	visited_starts = set()
	blocks = [ ]

	# take an initial exit and go
	symbolic_entry = z3.BitVecVal(entry, bits)
	remaining_exits.append(symbolic_irsb.SymbolicExit(symbolic_entry, { }, { }, [ ]))
	while remaining_exits:
		current_exit = remaining_exits[0]
		remaining_exits = remaining_exits[1:]

		# If we are calling, add the next instruction as another exit
		# TODO: actually handle this properly (taking into account the analysis of the function)
		if current_exit.after_ret is not None:
			cr_start = z3.BitVecVal(after_ret, bits)
			cr_reg = current_exit.registers
			cr_mem = current_exit.memory
			cr_con = current_exit.constraints
			remaining_exits.append(symbolic_irsb.SymbolicExit(cr_start, cr_reg, cr_mem, cr_con))

		# get the concrete value
		# TODO: deal with possibility of multiple exits
		concrete_start = symbolic_value.Value(current_exit.symbolic_target, current_exit.constraints).min
		byte_start = concrete_start - base
		if byte_start < 0 or byte_start >= len(bytes):
			l.warning("Exit jumps to %x, outside of the provided bytes." % concrete_start)
			continue

		if concrete_start not in visited_starts:
			visited_starts.add(concrete_start)
			sirsb = symbolic_irsb.SymbolicIRSB(base=base, bytes=bytes, byte_start=byte_start, constraints=current_exit.constraints)
			remaining_exits.extend(sirsb.exits())

			blocks.append((concrete_start - base, sirsb))

	return blocks

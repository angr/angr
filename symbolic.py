#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import idalink
import symbolic_irsb

import logging
l = logging.getLogger("symbolic")
l.setLevel(logging.DEBUG)

z3.init("/opt/python/lib/libz3.so")

######################
### Symbolic state ###
######################
import collections
State = collections.namedtuple("State", ("temps", "registers", "memory", "constraints", "id"))

class ConcretizingException(Exception):
	pass

def calc_concrete_start(symbolic_start, constraints):
	# if it's a constant, just return it
	if hasattr(symbolic_start, "as_long"):
		s = symbolic_start.as_long()
		l.debug("Got constant start: %x", s)
		return s

	# if it's not a constant, calculate it
	solver = z3.Solver()
	solver.add(*constraints)
	if solver.check() != z3.sat:
		raise ConcretizingException("Unsat exit condition in block.")

	s = solver.model().get_interp(symbolic_start).as_long()
	l.debug("Calculated concrete start: %x" % s)
	return s

def translate_one(base, bytes, byte_start, constraints):
	irsb = pyvex.IRSB(bytes = bytes[byte_start:], mem_addr = base + byte_start)
	if irsb.size() == 0:
		raise pyvex.VexException("Got empty IRSB at start address %x, byte offset %x." % (base + byte_start, byte_start))

	state = State({ }, { }, { }, [ ], str(base + byte_start))
	exits = symbolic_irsb.translate(irsb, state)

	irsb.pp()
	return irsb, exits, state

def translate_bytes(base, bytes, entry, bits=64):
	l.debug("Translating %d bytes, starting from %x" % (len(bytes), entry))
	symbolic_entry = z3.BitVecVal(entry, bits)
	remaining_exits = [ [ "", None, symbolic_entry, [ ] ] ]
	visited_starts = set()
	blocks = [ ]

	while remaining_exits:
		exit_type, last_imark, symbolic_start, block_constraints = remaining_exits[0]
		remaining_exits = remaining_exits[1:]

		if exit_type == "Ijk_Ret":
			# TODO: try to figure out where we're returning to, maybe
			continue

		if exit_type == "Ijk_Call":
			# add the next instruction as another exit
			# TODO: add constraints for the return from the called function
			remaining_exits.append([ "", None, z3.BitVecVal(last_imark.addr + last_imark.len, bits), block_constraints ])

		concrete_start = calc_concrete_start(symbolic_start, block_constraints)
		byte_start = concrete_start - base
		if byte_start < 0 or byte_start >= len(bytes):
			l.warning("Exit jumps to %x, outside of the provided bytes." % concrete_start)
			continue

		if concrete_start not in visited_starts:
			visited_starts.add(concrete_start)
			irsb, exits, state = translate_one(base, bytes, byte_start, block_constraints)
			remaining_exits.extend(exits)

			blocks.append((concrete_start - base, irsb))

	return blocks

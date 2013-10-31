#!/usr/bin/env python
'''This module handles constraint generation.'''

import os
import z3
import pyvex

# importing stuff into the module namespace
from s_value import ConcretizingException
from s_irsb import SymbolicIRSB, SymbolicIRSBError
from s_irstmt import SymbolicIRStmt
from s_exit import SymbolicExit
from s_state import SymbolicState
from s_memory import Memory, SymbolicMemoryError

# to make the stupid thing stop complaining
SymbolicIRStmt, ConcretizingException

import logging
l = logging.getLogger("pysex")

try:
	z3_path = os.environ["Z3PATH"]
except Exception:
	z3_path = "/opt/python/lib/"
z3.init(z3_path + "libz3.so")

def handle_exit_concrete(base, concrete_start, current_exit, bytes):
	byte_start = concrete_start - base
	irsb = pyvex.IRSB(bytes = bytes[byte_start:], mem_addr = base + byte_start, arch=current_exit.state.arch.vex_arch)
	sirsb = SymbolicIRSB(irsb=irsb, initial_state=current_exit.state)
	return sirsb

def concretize_exit(current_exit, fallback_state):
	sat_level = "constrained"

	# get the concrete value
	# TODO: deal with possibility of multiple exits
	l.debug("Concretizing start value...")

	#exit_state = current_exit.state

	# TODO: partial constraining
	#if not current_exit.reachable():
	#	l.warning("UNSAT exit condition. Falling back to fallback state.")
	#	sat_level = "fallback"
	#	current_exit.state = fallback_state

	#if not current_exit.reachable():
	#	l.warning("UNSAT exit condition. Falling back to unconstrained state.")
	#	sat_level = "unconstrained"
	#	current_exit.state = exit_state.copy_after()
	#	current_exit.state.clear_constraints()

	if not current_exit.reachable():
		l.warning("UNSAT exit condition with fallback state. Aborting.")
		return "unsat", None

	# now figure out how many values the exit has
	try:
		concrete_starts = [ current_exit.concretize() ]
	except ConcretizingException:
		max_multiple = 256
		concrete_starts = current_exit.concretize_n(max_multiple)

		l.debug("Got %d possibilities for exit." % len(concrete_starts))
		if len(concrete_starts) == max_multiple:
			l.warning("Exit concretized into the maximum number of targets. Ignoring.")
			concrete_starts = [ ]

	return sat_level, concrete_starts

def handle_exit(base, bytes, current_exit, fallback_state, visited_paths):
	exits_out = [ ]
	exits = [ ]
	sirsbs = { }
	sat_level, concrete_starts = concretize_exit(current_exit, fallback_state)

	if sat_level == "unsat" or len(concrete_starts) == 0:
		l.warning("Got no concrete values for the exit.")
	else:
		l.debug("Got SAT level: %s" % sat_level)
		for concrete_start in concrete_starts:
			l.debug("... concretized start: 0x%x" % concrete_start)
			byte_start = concrete_start - base
			if byte_start < 0 or byte_start >= len(bytes):
				l.info("Exit to 0x%x, outside of the provided bytes." % concrete_start)
				exits_out.append(current_exit)
				continue

			# TODO: more intelligent condition here to handle loops
			if concrete_start not in visited_paths:
				l.debug("... processing block")
				visited_paths.add(concrete_start)
				# Here it might raise exception inside pysex if we encounter
				# some instructions that VEX doesn't understand.
				# Let's catch it here to minimize its influences, so the
				# whole function that we have analyzed up to now will still be preserved.
				try:
					sirsb = handle_exit_concrete(base, concrete_start, current_exit, bytes)
				except SymbolicIRSBError:
					l.warning("Symbolic IRSB error caught. Skipping this one.", exc_info=True)
					continue

				sirsbs[concrete_start] = sirsb
				new_exits = sirsb.exits()
				l.debug("Got %d exits" % len(new_exits))
				exits.extend(new_exits)

	return sat_level, sirsbs, exits, exits_out



def translate_bytes(base, bytes, entry, initial_state = None, arch="AMD64"):
	l.debug("Translating %d bytes, starting from 0x%x" % (len(bytes), entry))
	remaining_exits = { }
	blocks = { }
	exit_types = ("constrained", "fallback", "unconstrained", "unsat")

	visited_paths = set()
	unsat_exits = [ ]
	exits_out = [ ]

	# take an initial exit
	if initial_state:
		l.debug("Received initial state.")

	entry_state = initial_state if initial_state else SymbolicState(arch=arch)
	entry_point = SymbolicExit(empty = True)
	entry_point.state = entry_state.copy_after()
	entry_point.s_target = z3.BitVecVal(entry, entry_state.arch.bits)
	entry_point.s_jumpkind = "Ijk_Boring"

	for exit_type in exit_types:
		remaining_exits[exit_type] = [ ]
		blocks[exit_type] = { }

	# TODO: maybe it's more appropriate to track how constrained it's been until now
	remaining_exits["constrained"].append(entry_point)

	# and go!
	for exit_type in exit_types:
		while remaining_exits[exit_type]:
			current_exit = remaining_exits[exit_type].pop()
			sat_level, irsbs, new_exits, new_exits_out = handle_exit(base, bytes, current_exit, entry_state.copy_after(), visited_paths)

			if sat_level == "unsat":
				unsat_exits.append(current_exit)

			# an exit can't re-constrain itself it it was deemed unconstrained earlier
			if exit_type != "constrained" and sat_level == "constrained":
				sat_level = exit_type

			blocks[sat_level].update(irsbs)
			remaining_exits[sat_level].extend(new_exits)
			exits_out.extend(new_exits_out)

	return blocks, exits_out, unsat_exits

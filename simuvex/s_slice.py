#!/usr/bin/env python

''' This file contains support for SimSlice. '''

import logging
l = logging.getLogger("s_slice")

import pyvex # pylint: disable=F0401
from .s_exception import SimError
from .s_path import SimPath

class SimSliceError(SimError):
	pass

class SimSlice(object):
	# SimSlice adds support for program slicing. It accepts a dict of all addresses
	# and analyzes a slice containing those addresses. The dict shows what possible
	# exits there are after a certain address.
	# Currently, code changes during the runtime of the slice are *not* supported.
	def __init__(self, initial_state, start_addr, addresses, callback, project, mode=None, options=None):

		# the paths that can be taken through this slice
		self.paths = [ SimPath(initial_state, mode=mode, options=options) ]
		self.last_addr_of_path = {}

		# prepare the states
		self.initial_state = initial_state

		# the callback function for making SimRuns
		self.callback = callback

		self.num_blocks = 0
		self.add_addresses(start_addr, addresses, project)

	def add_addresses(self, start_addr, addresses, project):
		max_inst_bytes = self.initial_state.arch.max_inst_bytes

		l.debug("Adding %d addresses to slice.", len(addresses))

		# make a one-instruction IRSB at the addresses
		instructions = [ ]
		stack = [ start_addr ]
		while len(stack) > 0:
			addr = stack.pop()
			if not project.is_sim_procedure(addr):
				irsb = pyvex.IRSB(bytes=self.initial_state.memory.read_from(addr, max_inst_bytes, concretization_constraints=[ ]), num_inst = 1, mem_addr=addr)
				first_imark = [ s for s in irsb.statements() if type(s) == pyvex.IRStmt.IMark ][0]

				l.debug("Instruction of size %d at 0x%x", first_imark.len, first_imark.addr)
				instructions.append((irsb, first_imark, None))
			else:
				instructions.append((None, None, addr))

			stack.extend(addresses[addr])

		l.debug("Sanity check: %d IMarks", len(instructions))

		# add the parts of the slice
		start_addr = None
		next_addr = None
		num_inst = 0
		num_bytes = 0
		for _, imark, pseudo_addr in instructions:
			if imark == None:
				# We come across a SimProcedure object
				# We are done with the previous slice, insert it first
				self.add_block(start_addr, num_inst, num_bytes, addresses)
				start_addr = None
				next_addr = None
				num_inst = 0
				num_bytes = 0

				l.debug("This should be a pseudo_addr for a SimProcedure. Handle it.")
				self.add_block(pseudo_addr, 0, 0, addresses)
			else:
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
					self.add_block(start_addr, num_inst, num_bytes, addresses)

					start_addr = imark.addr
					next_addr = imark.addr
					num_bytes = 0
					num_inst = 0

				next_addr += imark.len
				num_bytes += imark.len
				num_inst += 1
				if next_addr in addresses[start_addr]:
					addresses[start_addr].remove(next_addr)
					if next_addr in addresses:
						addresses[start_addr].extend(addresses[next_addr])

		l.debug("Adding final block of %d instructions and %d bytes starting at 0x%x", num_inst, num_bytes, start_addr)
		self.add_block(start_addr, num_inst, num_bytes, addresses)


	def add_block(self, addr, num_inst, num_bytes, addresses):
		# check current exit states for one that points to addr
		# if it doesn't exist, just take the last exit for now
		# replace the current exits with the new last one's exits

		new_paths = [ ]
		new_last_addr_of_path = {}

		#irsb = pyvex.IRSB(bytes=self.initial_state.memory.read_from(addr, num_bytes, concretization_constraints=[ ]), num_inst = num_inst, mem_addr=addr)
		#for path in self.paths:
		#	new_paths.extend(path.add_irsb(irsb, force=True))
		for path in self.paths:
			if path not in self.last_addr_of_path or addr in addresses[self.last_addr_of_path[path]]:
				paths = path.add_instructions(addr, num_inst, self.callback, num_bytes=num_bytes, force=True)
				new_paths.extend(paths)
				for p in paths:
					new_last_addr_of_path[p] = addr

		never_forced_paths = [ p for p in new_paths if not p.ever_forced ]
		last_nonforced_paths = [ p for p in new_paths if not p.last_forced ]

		l.debug("%d never_forced, %d last_nonforced, %d total paths", len(never_forced_paths), len(last_nonforced_paths), len(new_paths))

		if len(never_forced_paths) > 0:
			self.paths = never_forced_paths
			self.last_addr_of_path.clear()
			for p in self.paths:
				self.last_addr_of_path[p] = new_last_addr_of_path[p]
		elif len(last_nonforced_paths) > 0:
			self.paths = last_nonforced_paths
			self.last_addr_of_path.clear()
			for p in self.paths:
				self.last_addr_of_path[p] = new_last_addr_of_path[p]
		else:
			self.paths = new_paths
			self.last_addr_of_path = new_last_addr_of_path

		l.debug("%d new paths", len(self.paths))

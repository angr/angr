#!/usr/bin/env python

import os
import pyvex
import simuvex

from .binary import Binary
from .memory_dict import MemoryDict
from .exceptions import AngrException

import logging
l = logging.getLogger("angr.Project")

granularity = 0x1000000

class Project:
	def __init__(self, filename, arch="AMD64", load_libs=True):
		self.binaries = { }
		self.arch = arch
		self.dirname = os.path.dirname(filename)
		self.filename = os.path.basename(filename)

		l.info("Loading binary %s" % self.filename)
		self.binaries[self.filename] = Binary(filename, arch)
		self.min_addr = self.binaries[self.filename].min_addr()
		self.max_addr = self.binaries[self.filename].max_addr()
		self.entry = self.binaries[self.filename].entry()

		if load_libs:
			self.load_libs()
			self.resolve_imports()
		self.mem = MemoryDict(self.binaries)

	def find_delta(self, lib):
		min_addr_bin = lib.min_addr()
		max_addr_bin = lib.max_addr()

		l.debug("Calculating rebasing address of %s with address range (0x%x, 0x%x)" % (lib, min_addr_bin, max_addr_bin))

		# to avoid bugs, let's just relocate after for now, with a granularity between them
		start_offset = min_addr_bin % granularity
		new_start_bin = granularity * ((self.max_addr + granularity) / granularity) + start_offset
		l.debug("Binary %s will be allocated to 0x%x" % (lib, new_start_bin))
		delta = new_start_bin - min_addr_bin
		return delta

	def load_libs(self):
		remaining_libs = set(self.binaries[self.filename].get_lib_names())
		done_libs = set()

		# load all the libs
		while len(remaining_libs) > 0:
			lib = remaining_libs.pop()
			lib_path = os.path.join(self.dirname, lib)

			if lib not in done_libs and os.path.exists(lib_path):
				l.debug("Loading lib %s" % lib)
				done_libs.add(lib)
				# load new bin
				new_lib = Binary(lib_path, self.arch)
				self.binaries[lib] = new_lib

				# rebase new bin
				delta = self.find_delta(new_lib)
				l.debug("Rebasing lib %s by 0x%x" % (lib, delta))
				new_lib.rebase(delta)

				# update min and max addresses
				self.min_addr = min(self.min_addr, new_lib.min_addr())
				self.max_addr = max(self.max_addr, new_lib.max_addr())

				remaining_libs.update(new_lib.get_lib_names())

	def resolve_imports(self):
		for bin in self.binaries.values():
			resolved = { }

			for lib_name in bin.get_lib_names():
				if lib_name not in self.binaries:
					l.warning("Lib %s not provided/loaded. Can't resolve exports from this library." % lib_name)
					continue

				lib = self.binaries[lib_name]

				for export, type in lib.get_exports():
					try:
                                                resolved[export] = lib.get_symbol_addr(export, type)
					except Exception:
						l.warning("Unable to get address of export %s[%s] from bin %s. This happens sometimes." % (export, type, lib_name), exc_info=True)

			for imp, type in bin.get_imports():
				if imp in resolved:
					l.debug("Resolving import %s of bin %s to 0x%x" % (imp, bin.filename, resolved[imp]))
					bin.resolve_import(imp, resolved[imp])
				else:
					l.warning("Unable to resolve import %s of bin %s" % (imp, bin.filename))

	def functions(self):
		functions = { }
		for bin in self.binaries.values():
			functions.update(bin.functions(mem = self.mem))
		return functions

	# Returns a pyvex block starting at address addr
	#
	# Optional params:
	#
	#	max_size - the maximum size of the block, in bytes
	#	num_inst - the maximum number of instructions
	def block(self, addr, max_size=400, num_inst=None):
		# TODO: remove this ugly horrid hack
		try:
			bytes = self.mem[addr:addr+max_size]
		except KeyError as e:
			bytes = self.mem[addr:e.message]

		if not bytes:
			raise AngrException("No bytes in memory for block starting at 0x%x." % addr)

		if num_inst:
			return pyvex.IRSB(bytes=bytes, mem_addr=addr, num_inst=num_inst)
		else:
			return pyvex.IRSB(bytes=bytes, mem_addr=addr)

	# Returns a simuvex block starting at address addr
	#
	# Optional params:
	#
	#	max_size - the maximum size of the block, in bytes
	#	num_inst - the maximum number of instructions
	#	state - the initial state. Fully unconstrained if None
	#	mode - the simuvex mode (static, concrete, symbolic)
	def sim_block(self, addr, max_size=400, num_inst=None, state=None, mode="symbolic"):
		irsb = self.block(addr, max_size, num_inst)
		if not state: state = simuvex.SimState()

		return simuvex.SimIRSB(irsb, state, mode=mode)

	def make_refs(self):
		# TODO: uncomment
		#l.debug("Pulling all memory.")
		#self.mem.pull()

		loaded_state = simuvex.SimState(memory_backer=self.mem)
		sim_blocks = { }
		remaining_addrs = [ self.entry ]

		while len(remaining_addrs) > 0:
			a = remaining_addrs.pop()
			try:
				s = self.sim_block(a, state=loaded_state.copy_after(), mode="static")
			except AngrException:
				l.warning("Received AngrException trying to analyze block starting at 0x%x" % a, exc_info=True)
				continue

			sim_blocks[a] = s

			for ref_from,ref_to in s.code_refs:
				to_addr = ref_to.any()
				if to_addr not in sim_blocks:
					remaining_addrs.append(to_addr)

		self.static_sim_blocks = sim_blocks

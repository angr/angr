#!/usr/bin/env python

# pylint: disable=W0201
# pylint: disable=W0703

import os
import pyvex
import simuvex
import cPickle as pickle
import collections

from .binary import Binary
from .memory_dict import MemoryDict
from .errors import AngrException

import logging
l = logging.getLogger("angr.project")

granularity = 0x1000000

class Project:
	def __init__(self, filename, arch="AMD64", load_libs=True, use_abstract_procedures=False):
		self.binaries = { }
		self.arch = arch
		self.dirname = os.path.dirname(filename)
		self.filename = os.path.basename(filename)

		l.info("Loading binary %s" % self.filename)
		self.binaries[self.filename] = Binary(filename, arch)
		self.min_addr = self.binaries[self.filename].min_addr()
		self.max_addr = self.binaries[self.filename].max_addr()
		self.entry = self.binaries[self.filename].entry()

		if use_abstract_procedures:
			self.resolve_imports_using_abstract_procedures()
		if load_libs:
			self.load_libs()
			self.resolve_imports_from_libs()

		self.mem = MemoryDict(self.binaries, 'mem')
		self.perm = MemoryDict(self.binaries, 'perm', granularity=0x1000) # TODO: arch-dependent pages

	def save_mem(self):
		self.mem.pull()
		self.perm.pull()

		memfile = self.dirname + "/mem.p"
		pickle.dump((self.mem, self.perm), open(memfile, "w"))

	def load_mem(self):
		memfile = self.dirname + "/mem.p"
		self.mem, self.perm = pickle.load(open(memfile))

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

	def resolve_imports_from_libs(self):
		for b in self.binaries.values():
			resolved = { }

			for lib_name in b.get_lib_names():
				if lib_name not in self.binaries:
					l.warning("Lib %s not provided/loaded. Can't resolve exports from this library." % lib_name)
					continue

				lib = self.binaries[lib_name]

				for export, export_type in lib.get_exports():
					try:
						resolved[export] = lib.get_symbol_addr(export)
					except Exception:
						l.warning("Unable to get address of export %s[%s] from bin %s. This happens sometimes." % (export, export_type, lib_name), exc_info=True)

			for imp,_ in b.get_imports():
				if imp in resolved:
					l.debug("Resolving import %s of bin %s to 0x%x" % (imp, b.filename, resolved[imp]))
					b.resolve_import(imp, resolved[imp])
				else:
					l.warning("Unable to resolve import %s of bin %s" % (imp, b.filename))

	# Now it only supports the main binary!
	def resolve_imports_using_abstract_procedures(self):
		binary_name = self.filename
		binary = self.binaries[binary_name]
		for lib_name in binary.get_lib_names():
			l.debug("AbstractProc: lib_name: %s", lib_name)
			if lib_name in simuvex.procedures.SimProcedures:
				functions = simuvex.procedures.SimProcedures[lib_name]
				l.debug(functions)
				for imp, _ in binary.get_imports():
					l.debug("AbstractProc: import %s", imp)
					if imp in functions:
						l.debug("AbstractProc: %s found", imp)
						binary.set_abstract_func(lib_name, imp, functions[imp])

	def functions(self):
		functions = { }
		for b in self.binaries.values():
			functions.update(b.functions(mem = self.mem))
		return functions

	def binary_by_addr(self, addr):
		for b in self.binaries.itervalues():
			if b.min_addr() <= addr <= b.max_addr():
				return b

	# Returns a pyvex block starting at address addr
	#
	# Optional params:
	#
	#	max_size - the maximum size of the block, in bytes
	#	num_inst - the maximum number of instructions
	def block(self, addr, max_size=400, num_inst=None):
		# TODO: remove this ugly horrid hack
		try:
			buff = self.mem[addr:addr+max_size]
		except KeyError as e:
			buff = self.mem[addr:e.message]

		if not buff:
			raise AngrException("No bytes in memory for block starting at 0x%x." % addr)

		if num_inst:
			return pyvex.IRSB(bytes=buff, mem_addr=addr, num_inst=num_inst)
		else:
			return pyvex.IRSB(bytes=buff, mem_addr=addr)

	# Returns a simuvex block starting at address addr
	#
	# Optional params:
	#
	#	max_size - the maximum size of the block, in bytes
	#	num_inst - the maximum number of instructions
	#	state - the initial state. Fully unconstrained if None
	#	mode - the simuvex mode (static, concrete, symbolic)
	def sim_block(self, addr, state=None, max_size=400, num_inst=None, mode="symbolic"):
		irsb = self.block(addr, max_size, num_inst)
		if not state: state = simuvex.SimState(memory_backer=self.mem)

		return simuvex.SimIRSB(irsb, state, mode=mode)

	# Statically crawls the binary to determine code and data references. Creates
	# the following dictionaries:
	#
	#	data_reads_to - for each memory address, a list of instructions that read that address
	#	data_reads_from - for each instruction, a list of memory addresses and sizes that it reads
	#	data_writes_to - for each memory address, a list of instructions that write that address
	#	data_writes_from - for each instruction, list of memory addresses and sizes that it writes
	#	memory_refs_to - for each memory address, a list of instructions that reference it
	#	memory_refs_from - for each instruction, list of memory addresses that it references
	#	code_refs_to - for each code address, a list of instructions that jump/call to it
	#	code_refs_from - for each instruction, list of code addresses that it jumps/calls to
	def make_refs(self):
		l.debug("Pulling all memory.")
		self.mem.pull()
		self.perm.pull()

		loaded_state = simuvex.SimState(memory_backer=self.mem)
		sim_blocks = set()
		# TODO: add all entry points instead of just the first binary's entry point
		remaining_addrs = [ (self.entry, loaded_state.copy_after()) ]

		data_reads_to = collections.defaultdict(list)
		data_reads_from = collections.defaultdict(list)
		data_writes_to = collections.defaultdict(list)
		data_writes_from = collections.defaultdict(list)
		code_refs_to = collections.defaultdict(list)
		code_refs_from = collections.defaultdict(list)
		memory_refs_from = collections.defaultdict(list)
		memory_refs_to = collections.defaultdict(list)

		# Will be used later
		binary = self.binaries[self.filename]

		while len(remaining_addrs) > 0:
			(a, initial_state) = remaining_addrs.pop() # initial_state is used by abstract function!
			if not binary.is_abstract_func(a):
				l.debug("Analyzing non-abstract block 0x%08x" % a)
				try:
					s = self.sim_block(a, state=initial_state, mode="static")
				except (simuvex.SimIRSBError, AngrException):
					l.warning("Something wrong with block starting at 0x%x" % a, exc_info=True)
					continue

				#l.debug("Block at 0x%x got %d reads, %d writes, %d code, and %d ref", a, len(s.data_reads), len(s.data_writes), len(s.code_refs), len(s.memory_refs))
				sim_blocks.add(a)

				# track data reads
				for r in s.refs()[simuvex.SimMemRead]:
					if r.addr.is_symbolic():
						l.debug("Skipping symbolic ref.")
						continue

					val_to = r.addr.any()
					val_from = r.inst_addr
					l.debug("REFERENCE: memory read from 0x%x to 0x%x", val_from, val_to)
					data_reads_from[val_from].append((val_to, r.size/8))
					for i in range(val_to, val_to + r.size/8):
						data_reads_to[i].append(val_from)

				# track data writes
				for r in s.refs()[simuvex.SimMemWrite]:
					if r.addr.is_symbolic():
						l.debug("Skipping symbolic ref.")
						continue

					val_to = r.addr.any()
					val_from = r.inst_addr
					l.debug("REFERENCE: memory write from 0x%x to 0x%x", val_from, val_to)
					data_writes_to[val_to].append((val_from, r.size/8))
					for i in range(val_to, val_to + r.size/8):
						data_writes_to[i].append(val_from)

				# track code refs
				for r in s.refs()[simuvex.SimCodeRef]:
					if r.addr.is_symbolic():
						l.debug("Skipping symbolic ref at addr 0x%x.", r.inst_addr)
						continue

					val_to = r.addr.any()
					val_from = r.inst_addr
					l.debug("REFERENCE: code ref from 0x%x to 0x%x", val_from, val_to)
					code_refs_to[val_to].append(val_from)
					code_refs_from[val_from].append(val_to)

					# add the extra references
					if val_to not in sim_blocks:
						remaining_addrs.append((val_to, s.final_state))
						# TODO: Should we add 'a' to sim_blocks here? - Fish
						sim_blocks.add(val_to)

				# track memory refs
				for r in s.refs()[simuvex.SimMemRef]:
					if r.addr.is_symbolic():
						l.debug("Skipping symbolic ref.")
						continue

					val_to = r.addr.any()
					val_from = r.inst_addr
					l.debug("REFERENCE: memory ref from 0x%x to 0x%x", val_from, val_to)
					memory_refs_to[val_to].append(val_from)
					memory_refs_from[val_from].append(val_to)

					# add the extra references if they're in code
					# TODO: exclude references not in code
					if val_to not in sim_blocks and val_to in self.perm and self.perm[val_to] & 1:
						l.debug("... ADDING 0x%x to code", val_to)
						remaining_addrs.append((val_to, s.final_state))
						# TODO: Should we add 'a' to sim_blocks here? - Fish
						sim_blocks.add(val_to)
					elif val_to not in self.perm:
						l.debug("... 0x%x is not in perms", val_to)
					else:
						l.debug("... 0x%x is not code", val_to)
			else: # We have an abstract function for this block!
				sim_blocks.add(a)
				abstract_function = binary.get_abstract_func(a, initial_state)
				refs = abstract_function.refs()
				exits = abstract_function.exits()

				# data_reads_to.update(abstract_function.get_data_reads_to(initial_state))
				# data_reads_from.update(abstract_function.get_data_reads_from(initial_state))
				# data_writes_to.update(abstract_function.get_data_writes_to(initial_state))
				# data_writes_from.update(abstract_function.get_data_writes_from(initial_state))
				# code_refs_to.update(abstract_function.get_code_refs_to(initial_state))
				# code_refs_from.update(abstract_function.get_code_refs_from(initial_state))
				# memory_refs_to.update(abstract_function.get_memory_refs_to(initial_state))
				# memory_refs_from.update(abstract_function.get_memory_refs_from(initial_state))

				# Update exits!
				for ex in exits:
					addr_to = ex.concretize()
					if addr_to not in sim_blocks:
						sim_blocks.add(addr_to)
						remaining_addrs.append((addr_to, ex.state))
					l.debug("New exit provided by SimProcedure: 0x%08x", addr_to)

		self.data_reads_to = dict(data_reads_to)
		self.data_reads_from = dict(data_reads_from)
		self.data_writes_to = dict(data_writes_to)
		self.data_writes_from = dict(data_writes_from)
		self.code_refs_to = dict(code_refs_to)
		self.code_refs_from = dict(code_refs_from)
		self.memory_refs_from = dict(memory_refs_from)
		self.memory_refs_to = dict(memory_refs_to)
		self.static_block_addrs = sim_blocks

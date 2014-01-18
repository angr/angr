#!/usr/bin/env python

# pylint: disable=W0201
# pylint: disable=W0703

import os
import pyvex # pylint: disable=F0401
import simuvex # pylint: disable=F0401
import cPickle as pickle
import collections
import struct
import md5

from .binary import Binary
from .memory_dict import MemoryDict
from .errors import AngrException

import logging
l = logging.getLogger("angr.project")

granularity = 0x1000000

class Project(object):
	def __init__(self, filename, arch="AMD64", load_libs=True, use_sim_procedures=False, default_analysis_mode='static'):
		self.binaries = { }
		self.arch = arch
		self.dirname = os.path.dirname(filename)
		self.filename = os.path.basename(filename)
		self.default_analysis_mode = default_analysis_mode

		l.info("Loading binary %s" % self.filename)
		self.binaries[self.filename] = Binary(filename, arch)
		self.min_addr = self.binaries[self.filename].min_addr()
		self.max_addr = self.binaries[self.filename].max_addr()
		self.entry = self.binaries[self.filename].entry()
		self.sim_procedures = { } # This is a map from IAT addr to SimProcedure

		if load_libs:
			self.load_libs()
			self.resolve_imports_from_libs()
		if use_sim_procedures:
			self.resolve_imports_using_sim_procedures()

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
	def resolve_imports_using_sim_procedures(self):
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
						self.set_sim_procedure(binary, lib_name, imp, functions[imp])

	def functions(self):
		functions = { }
		for b in self.binaries.values():
			functions.update(b.functions(mem = self.mem))
		return functions

	def binary_by_addr(self, addr):
		for b in self.binaries.itervalues():
			if b.min_addr() <= addr <= b.max_addr():
				return b

	# Creates an initial state, with stack and everything.
	def initial_state(self):
		s = simuvex.SimState(memory_backer=self.mem, arch=self.arch).copy_after()

		# Initialize the stack pointer
		if s.arch.name == "AMD64":
			s.store_reg(s.arch.sp_offset, 0xfffffffffff0000, 8)
		else:
			raise Exception("Architecture %s is not supported." % s.arch.name)
		return s

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
	def sim_block(self, addr, state=None, max_size=400, num_inst=None, options=None, mode=None):
		if mode is None:
			mode = self.default_analysis_mode

		irsb = self.block(addr, max_size, num_inst)
		if not state: state = self.initial_state()

		return simuvex.SimIRSB(state, irsb, options=options, mode=mode)

	# Returns a simuvex SimRun object (supporting refs() and exits()), automatically choosing
	# whether to create a SimIRSB or a SimProcedure.
	#
	# Params:
	#
	#	where - either an exit or an address to analyze
	#	state - the state to pass to the analysis. If this is blank, a new state is created when using
	#		an address and an exit's state is used when using an exit
	#	max_size - the maximum size of the block, in bytes
	#	num_inst - the maximum number of instructions
	#	state - the initial state. Fully unconstrained if None
	#	mode - the simuvex mode (static, concrete, symbolic)
	def sim_run(self, where, state=None, max_size=400, num_inst=None, options=None, mode=None):
		if isinstance(where, simuvex.SimExit):
			if where.jumpkind.startswith('Ijk_Sys'):
				return simuvex.SimProcedures['syscalls']['handler'](where.state)
			# TODO: multi-valued exits
			addr = where.concretize()
			if not state: state = where.state
		else:
			addr = where
			if not state: state = self.initial_state()

		if self.is_sim_procedure(addr):
			sim_proc = self.get_sim_procedure(addr, state)
			return sim_proc
		else:
			return self.sim_block(addr, state, max_size, num_inst, options, mode)


	def set_sim_procedure(self, binary, lib, func_name, sim_proc):
		# Get address of that import
		plt_addrs = binary.get_import_addrs(func_name)
		# Generate a hashed address for this function, which is used for indexing the abstrct
		# function later.
		# This is so hackish, but thanks to the fucking constraints, we have no better way to handle this
		m = md5.md5()
		m.update(lib + "_" + func_name)
		# TODO: update addr length according to different system arch
		hashed_bytes = m.digest()[ : 8]
		pseudo_addr = struct.unpack("<Q", hashed_bytes)[0]
		# Put it in our dict
		self.sim_procedures[pseudo_addr] = sim_proc
		print self.sim_procedures.items()
		for addr in plt_addrs:
			for n, p in enumerate(hashed_bytes):
				binary.ida.mem[addr + n] = p

	def is_sim_procedure(self, hashed_addr):
		return hashed_addr in self.sim_procedures

	def get_sim_procedure(self, hashed_addr, state):
		if hashed_addr in self.sim_procedures:
			return self.sim_procedures[hashed_addr](state)
		else:
			return None

	def loop_iteration(self, entry_exit, addresses, max_runs=100):
		if max_runs == 0:
			l.warning("Reached max_runs in loop_iteration. This could indicate a nested loop!!!!")
			return [ ], [ ]

		sirsb = self.sim_run(entry_exit)
		imarks = set(sirsb.imark_addrs())

		l.debug("Got SimRun %s", sirsb.__class__.__name__)
		if isinstance(sirsb, simuvex.SimIRSB):
			l.debug("... start addr: 0x%x", sirsb.first_imark.addr)

		if addresses[0] in imarks:
			l.debug("Found head address in IRSB!")
			return [ entry_exit ], [ ], [ ]

		# If we're here, this isn't a loop header, check if it's an exit out of the loop
		if len(set(addresses) & imarks) == 0:
			return [ ], [ entry_exit ], [ ]

		# Otherwise, keep digging
		head_exits = [ ]
		other_exits = [ ]
		reachable_exits = [ e for e in sirsb.flat_exits() if e.reachable() ]
		unreachable_exits = [ e for e in sirsb.flat_exits() if not e.reachable() ]

		l.debug("reachable_exits: %d", len(reachable_exits))
		for e in reachable_exits:
			more_head, more_other, unreachables = self.loop_iteration(e, addresses, max_runs=max_runs-1)
			head_exits.extend(more_head)
			other_exits.extend(more_other)
			unreachable_exits.extend(unreachables)

		l.debug("head_exits: %d", len(head_exits))
		l.debug("other_exits: %d", len(other_exits))
		l.debug("unreachable_exits: %d", len(unreachable_exits))

		return head_exits, other_exits, unreachable_exits

	def unconstrain_head(self, head_entry, addresses, registers=True, memory=True, runs_per_iter=100):
		l.debug("Unconstraining loop header!")

		sirsb = self.sim_run(head_entry)

		reachable_exits = [ e for e in sirsb.flat_exits() if e.reachable() and e.concretize() in addresses ]
		l.debug("%d reachable exits from last header", len(reachable_exits))

		final_head_entries = [ ]
		for e in reachable_exits:
			final_head_entries.extend(self.loop_iteration(e, addresses, runs_per_iter)[0])
		l.debug("%d final head entries", len(final_head_entries))

		final_head_runs = [ ]
		for e in final_head_entries:
			final_head_runs.append(self.sim_run(e))
		l.debug("%d final head runs", len(final_head_runs))

		final_head_exits = [ ]
		for head_sb in final_head_runs:
			final_head_exits.extend(head_sb.flat_exits())
		l.debug("%d final head_exits", len(final_head_exits))

		unconstrained_states = [ ]
		#state_mods = set()
		for e in final_head_exits:
			ustate = sirsb.initial_state.copy_after()

			# TODO: this part actually filters out things that do the same number of
			# 	mem/reg changes but add different constraints. We probably shouldn't do this.
			#cb_mem = frozenset()
			#cb_regs = frozenset()
			#if registers: cb_regs = frozenset(ustate.registers.changed_bytes(e.state.registers))
			#if memory: cb_mem = frozenset(ustate.memory.changed_bytes(e.state.memory))
			#if (cb_mem, cb_regs) in state_mods:
			#	continue
			#else:
			#	state_mods.add((cb_mem, cb_regs))

			if registers: ustate.memory.unconstrain_differences(e.state.memory)
			if memory: ustate.registers.unconstrain_differences(e.state.registers)
			unconstrained_states.append(ustate)
		l.debug("%d unconstrained states", len(unconstrained_states))

		unconstrained_exits = [ ]
		for s in unconstrained_states:
			head_entry.state = s
			l.debug("|||| Analyzing a run.")
			final_heads, final_others, unreachables = self.loop_iteration(head_entry, addresses, runs_per_iter)

			# TODO: if there are still some unreachables here, we might have to amp up our escape strategy

			l.debug(".... unconstrained: %d head, %d other, %d unsat", len(final_heads), len(final_others), len(unreachables))
			unconstrained_exits.extend(final_others)
			for f in final_heads:
				unconstrained_run = self.sim_run(f)
				unconstrained_exits.extend(unconstrained_run.flat_exits())

		loop_exits = [ e for e in unconstrained_exits if e.concretize() not in addresses]
		l.debug("Found %d unconstrained exits out of the the loop!", len(loop_exits))

		return loop_exits

	# Attempts to escape from a loop
	def escape_loop(self, entry_exit, addresses, max_iterations=0, runs_per_iter=100):
		normal_exits = [ ]

		# First, go through the loop the right about of iterations
		current_heads = [ entry_exit ]
		while max_iterations > 0:
			if len(current_heads) != 1:
				raise Exception("Multiple heads in escape_loop(). While this isn't bad, it needs to be thought about.")

			new_head = [ ]
			for c_h in current_heads:
				heads, new_other, _ = self.loop_iteration(c_h, addresses, runs_per_iter)
				normal_exits.extend(new_other)
				new_head.extend(heads)
			current_heads = new_head
			max_iterations -= 1

		l.debug("Collected %d normal exits and %d heads for unconstraining", len(normal_exits), len(current_heads))

		# Now, go through the remaining head exits, run them one more time, unconstrain the results, run them one more time, and get the exits
		unconstrained_exits = [ ]
		for h in current_heads:
			unconstrained_exits.extend(self.unconstrain_head(h, addresses, runs_per_iter))

		l.debug("Created %d unconstrained exits", len(unconstrained_exits))

		return { 'constrained': normal_exits, 'unconstrained': unconstrained_exits }


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

		while len(remaining_addrs) > 0:
			(a, initial_state) = remaining_addrs.pop() # initial_state is used by abstract function!
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
					remaining_addrs.append((val_to, s.state))
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
					remaining_addrs.append((val_to, s.state))
					# TODO: Should we add 'a' to sim_blocks here? - Fish
					sim_blocks.add(val_to)
				elif val_to not in self.perm:
					l.debug("... 0x%x is not in perms", val_to)
				else:
					l.debug("... 0x%x is not code", val_to)

		self.data_reads_to = dict(data_reads_to)
		self.data_reads_from = dict(data_reads_from)
		self.data_writes_to = dict(data_writes_to)
		self.data_writes_from = dict(data_writes_from)
		self.code_refs_to = dict(code_refs_to)
		self.code_refs_from = dict(code_refs_from)
		self.memory_refs_from = dict(memory_refs_from)
		self.memory_refs_to = dict(memory_refs_to)
		self.static_block_addrs = sim_blocks

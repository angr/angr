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

class Project(object): # pylint: disable=R0904,
	def __init__(self, filename, arch="AMD64", binary_base_addr=None, load_libs=True, resolve_imports=True, use_sim_procedures=False, default_analysis_mode='static'):
		self.binaries = { }
		self.arch = arch
		self.dirname = os.path.dirname(filename)
		self.filename = os.path.basename(filename)
		self.default_analysis_mode = default_analysis_mode

		l.info("Loading binary %s" % self.filename)
		l.debug("... from directory: %s", self.dirname)
		self.binaries[self.filename] = Binary(filename, arch, base_addr=binary_base_addr)
		self.min_addr = self.binaries[self.filename].min_addr()
		self.max_addr = self.binaries[self.filename].max_addr()
		self.entry = self.binaries[self.filename].entry()
		self.sim_procedures = { } # This is a map from IAT addr to SimProcedure

		if load_libs:
			self.load_libs()
			if resolve_imports:
				self.resolve_imports_from_libs()
		if use_sim_procedures:
			self.resolve_imports_using_sim_procedures()

		self.mem = MemoryDict(self.binaries, 'mem')
		self.perm = MemoryDict(self.binaries, 'perm', granularity=0x1000) # TODO: arch-dependent pages

		self.mem.pull()

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

	def next_base(self):
		base = self.max_addr + (granularity - self.max_addr % granularity)
		return base

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
				new_lib = Binary(lib_path, self.arch, base_addr=self.next_base())
				self.binaries[lib] = new_lib

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
					try:
						b.resolve_import(imp, resolved[imp])
					except Exception:
						l.warning("Mismatch between IDA info and ELF info. Symbols %s in bin %s" % (imp, b.filename))
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
				#l.debug(functions)
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
		elif s.arch.name == "ARM":
			s.store_reg(s.arch.sp_offset, 0xffff0000, 4)
		else:
			raise Exception("Architecture %s is not supported." % s.arch.name)
		return s

	# Creates a SimExit to the entry point.
	def initial_exit(self):
		return simuvex.SimExit(addr=self.entry, state=self.initial_state())

	# Returns a pyvex block starting at address addr
	#
	# Optional params:
	#
	#	max_size - the maximum size of the block, in bytes
	#	num_inst - the maximum number of instructions
	def block(self, addr, max_size=None, num_inst=None):
		max_size = 400 if max_size is None else max_size

		# TODO: remove this ugly horrid hack
		try:
			buff = self.mem[addr:addr+max_size]
		except KeyError as e:
			buff = self.mem[addr:e.message]

		# deal with thumb mode in ARM, sending an odd address and an offset into the string
		byte_offset = 0
		if self.arch == "ARM" and self.binary_by_addr(addr).ida.idc.GetReg(addr, "T") == 1:
			addr += 1
			byte_offset = 1

		if not buff:
			raise AngrException("No bytes in memory for block starting at 0x%x." % addr)

		l.debug("Creating pyvex.IRSB of arch %s at 0x%x", self.arch, addr)
		vex_arch = "VexArch" + self.arch

		if num_inst:
			return pyvex.IRSB(bytes=buff, mem_addr=addr, num_inst=num_inst, arch=vex_arch, bytes_offset=byte_offset)
		else:
			return pyvex.IRSB(bytes=buff, mem_addr=addr, arch=vex_arch, bytes_offset=byte_offset)

	# Returns a simuvex block starting at address addr
	#
	# Optional params:
	#
	#	max_size - the maximum size of the block, in bytes
	#	num_inst - the maximum number of instructions
	#	state - the initial state. Fully unconstrained if None
	#	mode - the simuvex mode (static, concrete, symbolic)
	def sim_block(self, addr, state=None, max_size=None, num_inst=None, options=None, mode=None, stmt_whitelist=None, last_stmt=None):
		if mode is None:
			mode = self.default_analysis_mode

		irsb = self.block(addr, max_size, num_inst)
		if not state: state = self.initial_state()

		return simuvex.SimIRSB(state, irsb, options=options, mode=mode, whitelist=stmt_whitelist, last_stmt=last_stmt)

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
	def sim_run(self, where, state=None, max_size=400, num_inst=None, options=None, mode=None, stmt_whitelist=None, last_stmt=None):
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

			l.debug("Creating SimProcedure %s (originally at 0x%x)", sim_proc.__class__.__name__, addr)
			return sim_proc
		else:
			l.debug("Creating SimIRSB at 0x%x", addr)
			return self.sim_block(addr, state=state, max_size=max_size, num_inst=num_inst, options=options, mode=mode, stmt_whitelist=stmt_whitelist, last_stmt=last_stmt)


	def set_sim_procedure(self, binary, lib, func_name, sim_proc):
		# Generate a hashed address for this function, which is used for indexing the abstrct
		# function later.
		# This is so hackish, but thanks to the fucking constraints, we have no better way to handle this
		m = md5.md5()
		m.update(lib + "_" + func_name)
		# TODO: update addr length according to different system arch
		hashed_bytes = m.digest()[ : binary.bits/8]
		pseudo_addr = struct.unpack(binary.struct_format, hashed_bytes)[0]
		# Put it in our dict
		self.sim_procedures[pseudo_addr] = sim_proc
		l.debug("Setting SimProcedure %s with psuedo_addr 0x%x...", func_name, pseudo_addr)

		# Update all the stubs for the function
		binary.resolve_import(func_name, pseudo_addr)

	def is_sim_procedure(self, hashed_addr):
		return hashed_addr in self.sim_procedures

	def get_sim_procedure(self, hashed_addr, state):
		if hashed_addr in self.sim_procedures:
			return self.sim_procedures[hashed_addr](state, addr=hashed_addr)
		else:
			return None

	def get_pseudo_addr_for_sim_procedure(self, s_proc):
		for addr, class_ in self.sim_procedures.items():
			if isinstance(s_proc, class_):
				return addr
		return None

	# Explores the path space until a block containing a specified address is found.
	#
	# Params:
	#
	#	start - a SimExit pointing to the start of the analysis
	#	find - a tuple containing the addresses to search for
	#	avoid - a tuple containing the addresses to avoid
	#	restrict - a tuple containing the addresses to restrict the analysis to (i.e., avoid all others)
	#	min_depth - the minimum number of SimRuns in the resulting path
	#	max_depth - the maximum number of SimRuns in the resulting path
	#	path_limit - if more than this number of paths are seen during the analysis, sample it down to this number
	#	max_repeats - the maximum number of times a single instruction can be seen before the analysis is aborted
	#	fast_found - stop the analysis as soon as a target is found
	#	fast_deviant - stop the analysis as soon as the path leaves the restricted-to addresses
	#	fast_avoid - stop the analysis as soon as the path hits an avoided address
	#
	#	mode - the mode of the analysis
	#	options - the options of the analysis
	#		- if both mode and options are None, the default analysis mode is used
	def explore(self, start, find = (), avoid = (), restrict = (), min_depth=0, max_depth=100, path_limit=20, max_repeats=1, mode=None, options=None, fast_found=True, fast_deviant=False, fast_avoid=False):
		# TODO: loops
		# TODO: avoidance of certain addresses
		if mode is None and options is None:
			mode = self.default_analysis_mode

		# get our initial path set up
		start_path = simuvex.SimPath(start.state, entry_exit=start, mode=mode, options=options)

		# initialize the counter
		instruction_counter = collections.Counter()

		# turn our tuples of crap into sets
		find = set(find)
		avoid = set(avoid)
		restrict = set(restrict)

		normal_paths = [ start_path ]
		found_paths = [ ]
		avoid_paths = [ ]
		deviant_paths = [ ]
		for i in range(0, max_depth):
			l.debug("At depth %d out of %d (maxdepth), with %d paths.", i, max_depth, len(normal_paths))

			new_paths = [ ]
			for p in normal_paths:
				new_paths.extend(p.continue_path(self.sim_run))

			# just do this for now if we're below the limit
			if i < min_depth:
				normal_paths = new_paths
				continue

			# now split the paths out
			normal_paths = [ ]
			for p in new_paths:
				if isinstance(p.last_run, simuvex.SimIRSB):
					imark_set = set(p.last_run.imark_addrs())
					for addr in imark_set:
						instruction_counter[addr] += 1

					find_intersection = imark_set & find
					avoid_intersection = imark_set & avoid
					restrict_intersection = imark_set & restrict

					if len(avoid_intersection) > 0:
						l.debug("Avoiding path %s due to matched avoid addresses: %s", p, avoid_intersection)
						avoid_paths.append(p)
					elif p.length >= min_depth and len(find_intersection) > 0:
						l.debug("Keeping path %s due to matched target addresses: %s", p, find_intersection)
						found_paths.append(p)
					elif len(restrict) > 0 and len(restrict_intersection) == 0:
						l.debug("Path %s is not on the restricted addresses!", p)
						deviant_paths.append(p)
					else:
						normal_paths.append(p)
				else:
					normal_paths.append(p)

			# abort if we've repeated an instruction more times than max_repeats
			if instruction_counter.most_common()[0][1] > max_repeats: break

			# abort if we're out of paths
			if len(normal_paths) == 0: break

			# sample the paths if there are too many
			# TODO: intelligent path sampling
			if len(normal_paths) > path_limit:
				#normal_paths = random.sample(normal_paths, path_limit)
				normal_paths = normal_paths[:path_limit]

			# break if specified conditions are met
			if fast_found and len(found_paths) > 0: break
			if fast_deviant and len(deviant_paths) > 0: break
			if fast_avoid and len(avoid_paths) > 0: break

		l.debug("Result: %d normal, %d found, %d avoided, %d deviating", len(normal_paths), len(found_paths), len(avoid_paths), len(deviant_paths))
		return { 'normal': normal_paths, 'found': found_paths, 'avoided': avoid_paths, 'deviating': deviant_paths, 'instruction_counts': dict(instruction_counter) }

	def unconstrain_head(self, constrained_entry, addresses, registers=True, memory=True, runs_per_iter=100):
		l.debug("Unconstraining loop header!")

		# first, go through the loop normally, one more time
		constrained_results = self.explore(constrained_entry, find=(addresses[0],), min_depth=1, restrict=addresses, max_depth=runs_per_iter, max_repeats=1)
		l.debug("%d paths to header found", len(constrained_results['found']))

		# then unconstrain differences between the original state and any new head states
		constrained_state = constrained_entry.state
		unconstrained_states = [ ]
		for p in constrained_results['found']:
			# because the head_entry might actually point partway *through* the loop header, in the cases of a loop starting between
			# the counter-increment and the condition check (because the counter is only incremented at the end of the loop, and the
			# end is placed in the beginning for optimization), so we run the loop through to the *end* of the header
			header_exits = p.last_run.flat_exits(reachable=True)
			for e in header_exits:
				new_state = e.state.copy_after()
				if registers: new_state.registers.unconstrain_differences(constrained_state.registers)
				if memory: new_state.memory.unconstrain_differences(constrained_state.memory)
				unconstrained_states.append(new_state)
		l.debug("%d unconstrained states", len(unconstrained_states))

		# then go through the loop one more time and return the exits
		unconstrained_exits = [ ]
		unconstrained_entry = constrained_entry
		for s in unconstrained_states:
			unconstrained_entry.state = s
			unconstrained_results = self.explore(unconstrained_entry, find=(addresses[0],), min_depth=1, restrict=addresses, max_depth=runs_per_iter, max_repeats=1)
			for p in unconstrained_results['deviating']:
				unconstrained_exits.append(simuvex.SimExit(addr=p.last_run.first_imark.addr, state=p.last_run.initial_state))

		l.debug("Found %d unconstrained exits out of the the loop!", len(unconstrained_exits))
		return unconstrained_exits

	# Attempts to escape from a loop
	def escape_loop(self, entry_exit, addresses, max_iterations=0, runs_per_iter=100):
		normal_exits = [ ]

		l.info("Going through the loop until we give up (%d iterations).", max_iterations)
		# First, go through the loop the right about of iterations
		current_heads = [ entry_exit ]
		while max_iterations > 0:
			if len(current_heads) != 1:
				raise Exception("Multiple heads in escape_loop(). While this isn't bad, it needs to be thought about.")

			new_head = [ ]
			for c_h in current_heads:
				results = self.explore(c_h, find=(addresses[0],), restrict=addresses, max_depth=runs_per_iter, max_repeats=1)
				for p in results['deviating']:
					normal_exits.extend(p.flat_exits(reachable=True))
				for p in results['found']:
					new_head.extend(p.flat_exits(reachable=True))
			current_heads = new_head
			max_iterations -= 1

		l.info("Collected %d normal exits and %d heads for unconstraining", len(normal_exits), len(current_heads))

		# Now unconstrain the remaining heads
		unconstrained_exits = [ ]
		for h in current_heads:
			unconstrained_exits.extend(self.unconstrain_head(h, addresses, runs_per_iter))

		l.info("Created %d unconstrained exits", len(unconstrained_exits))
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

#!/usr/bin/env python

import logging
l = logging.getLogger("angr.path")

from .errors import AngrMemoryError, AngrExitError, AngrPathError
import simuvex
import claripy

import cPickle as pickle
import collections

class Path(object):
	def __init__(self, project=None, entry=None):
		# This exit is used if this path is continued with a None last_run
		self._entry = entry

		# the length of the path
		self.length = 0
		self.extra_length = 0 # additions to the lengths (for weighting purposes)

		# project
		self._project = project

		# the last block that was processed
		self.last_run = None

		# this path's backtrace
		self.backtrace = [ ]
		self.addr_backtrace = [ ]
		self.callstack = [ ]

		# loop detection
		self.blockcounter_stack = [ collections.Counter() ]

		# the refs
		self._refs = [ ]

		# these are exits that had errors
		self.errored = [ ]

		# for merging
		self._upcoming_merge_points = [ ]
		self._merge_flags = [ ]
		self._merge_values = [ ]
		self._merge_backtraces = [ ]
		self._merge_addr_backtraces = [ ]
		self._merge_depths = [ ]

		# for pickling
		self._pickle_addr = None
		self._pickle_state_id = None
		self._pickle_whitelist = None
		self._pickle_last_stmt = None

	def detect_loops(self, n=None): #pylint:disable=unused-argument
		'''
		Returns the current loop iteration that a path is on.

		@param n: the minimum number of iterations to check for.
		@returns the number of the loop iteration it's in
		'''

		# TODO: make this work better
		#addr_strs = [ "%x"%x for x in self.addr_backtrace ]
		#bigstr = "".join(addr_strs)

		#candidates = [ ]

		#max_iteration_length = len(self.addr_backtrace) / n
		#for i in range(max_iteration_length):
		#	candidates.append("".join(addr_strs[-i-0:]))

		#for c in reversed(candidates):
		#	if bigstr.count(c) >= n:
		#		return n
		#return None

		return self.blockcounter_stack[-1].most_common()[0][1]

	def exits(self, reachable=None, symbolic=None, concrete=None):
		if self.last_run is None and self._entry is not None:
			return self._entry if self._entry is not None else [ ]
		return self.last_run.exits(reachable=reachable, symbolic=symbolic, concrete=concrete)

	def flat_exits(self, reachable=None, symbolic=None, concrete=None):
		if self.last_run is None and self._entry is not None:
			return self._entry.split() if self._entry is not None else [ ]
		return self.last_run.flat_exits(reachable=reachable, symbolic=symbolic, concrete=concrete)

	def continue_through_exit(self, e, stmt_whitelist=None, last_stmt=None, copy=True):
		e.state._inspect('exit', simuvex.BP_AFTER, backtrace=self.addr_backtrace)

		#try:
		new_run = self._project.sim_run(e, stmt_whitelist=stmt_whitelist, last_stmt=last_stmt)
		#except (AngrExitError, AngrMemoryError, simuvex.SimError, simuvex.SimValueError, claripy.UnsatError):
		#	l.warning("continue_through_exit() got exception at 0x%x.", e.concretize(), exc_info=True)
		#	self.errored.append(e)
		#	return None

		if copy:
			new_path = self.copy()
		else:
			new_path = self
		new_path.add_run(new_run, jumpkind=e.jumpkind)
		return new_path

	def continue_path(self):
		''''
		Continues the path by sending all of the exits through the "callback"
		function (which must accept a SimExit and a set of options) to create
		new SimRuns, then branching off paths for all of them.
		'''

		exits = self.flat_exits(reachable=True)
		l.debug("Got %d exits", len(exits))

		new_paths = [ ]
		for e in exits:
			new_path = self.continue_through_exit(e)
			if new_path is not None:
				new_paths.append(new_path)

		l.debug("Continuing path with %d new paths.", len(new_paths))
		return new_paths

	def refs(self):
		return self._refs

	def copy_refs(self, other):
		self._refs.extend(other.refs())

	# Adds a run to the path
	def add_run(self, srun, jumpkind=None):
		l.debug("Extending path with: %s", srun)

		# maintain the blockcounter stack
		if jumpkind == "Ijk_Call":
			l.debug("... it's a call!")
			self.callstack.append((self.last_run.addr, srun.addr))
			self.blockcounter_stack.append(collections.Counter())
		elif jumpkind == "Ijk_Ret":
			l.debug("... it's a ret!")
			self.blockcounter_stack.pop()
			if len(self.blockcounter_stack) == 0:
				l.debug("... WARNING: unbalanced callstack")
				self.blockcounter_stack.append(collections.Counter())

			if len(self.callstack) > 0:
				self.callstack.pop()

		# maintain the blockstack
		self.backtrace.append(str(srun))
		self.addr_backtrace.append(srun.addr)
		self.blockcounter_stack[-1][srun.addr] += 1

		self.length += 1
		self.last_run = srun
		# NOTE: we currently don't record refs, as this causes old states
		# not to be deleted and uses up TONS of memory
		#self.copy_refs(srun)

	#
	# helpers
	#

	@property
	def last_addr(self):
		if self.last_run is not None:
			return self.last_run.addr
		else:
			return self._pickle_addr

	@property
	def last_initial_state(self):
		if self.last_run is not None:
			return self.last_run.initial_state
		else:
			return pickle.load(open("pickle/state-%d.p" % self._pickle_state_id))

	@property
	def _s(self):
		return self.last_initial_state

	@property
	def _r(self):
		return self.last_run

	@property
	def weighted_length(self):
		return self.length + self.extra_length

	#
	# Copying, merging, splitting, etc
	#

	def copy(self):
		'''
		Returns a copy of the Path.
		'''
		l.debug("Copying path %s", self)
		o = Path(project=self._project)
		o.copy_refs(self)

		o.addr_backtrace = [ s for s in self.addr_backtrace ]
		o.backtrace = [ s for s in self.backtrace ]
		o.blockcounter_stack = [ collections.Counter(s) for s in self.blockcounter_stack ]
		o.callstack = self.callstack[:]
		o.length = self.length
		o.last_run = self.last_run
		o._upcoming_merge_points = list(self._upcoming_merge_points)
		o._merge_flags = list(self._merge_flags)
		o._merge_values = list(self._merge_values)
		o._merge_backtraces = list(self._merge_backtraces)
		o._merge_addr_backtraces = list(self._merge_addr_backtraces)
		o._merge_depths = list(self._merge_depths)

		return o

	def unmerge(self):
		'''
		Unmerges the state back into different possible states.
		'''

		l.debug("Unmerging %s!", self)

		states = [ self.last_initial_state ]

		for flag,values in zip(self._merge_flags, self._merge_values):
			l.debug("... processing %s with %d possibilities", flag, len(values))

			new_states = [ ]

			for v in values:
				for s in states:
					s_copy = s.copy()
					s_copy.add_constraints(flag == v)
					new_states.append(s_copy)

			states = [ s for s in new_states if s.satisfiable() ]
			l.debug("... resulting in %d satisfiable states", len(states))

		new_paths = [ ]
		for s in states:
			s.simplify()

			p = self.copy()
			p.last_run = self.last_run.reanalyze(new_state=s)
			new_paths.append(p)
		return new_paths

	def merge(self, *others):
		'''
		Returns a merger of this path with *others.
		'''
		all_paths = list(others) + [ self ]
		if len(set([ o.last_addr for o in all_paths])) != 1:
			raise AngrPathError("Unable to merge paths.")

		# merge the state
		new_path = self.copy()
		new_state, merge_flag = self.last_initial_state.merge(*[ o.last_initial_state for o in others ])

		# fix the backtraces
		divergence_index = [ len(set(addrs)) == 1 for addrs in zip(*[ o.addr_backtrace for o in all_paths ]) ].index(False)
		new_path.addr_backtrace = self.addr_backtrace[:divergence_index]
		new_path.addr_backtrace.append(-1)
		new_path.backtrace = self.backtrace[:divergence_index]
		new_path.backtrace.append(("MERGE POINT: %s" % merge_flag))

		# continue the path
		e = simuvex.SimExit(state=new_state, addr=self.last_addr, state_is_raw=True)
		new_path.continue_through_exit(e, copy=False)

		# reset the upcoming merge points
		new_path._upcoming_merge_points = [ ]
		new_path._merge_flags.append(merge_flag) # pylint: disable=W0212,
		new_path._merge_values.append(list(range(len(all_paths)))) # pylint: disable=W0212,
		new_path._merge_backtraces.append( [ o.backtrace for o in all_paths ] ) # pylint: disable=W0212,
		new_path._merge_addr_backtraces.append( [ o.addr_backtrace for o in all_paths ] ) # pylint: disable=W0212,
		new_path._merge_depths.append(new_path.length) # pylint: disable=W0212,

		return new_path

	def suspend(self, do_pickle=True):
		'''
		Suspends the path for spilling/pickling.
		'''
		l.debug("%s suspending...", self)

		if do_pickle:
			self._pickle_state_id = id(self.last_initial_state)
			self._pickle_addr = self.last_addr
			self._pickle_whitelist = getattr(self.last_run, 'whitelist', None)
			self._pickle_last_stmt = getattr(self.last_run, 'last_stmt', None)

			l.debug("... pickling the initial state")
			pickle.dump(self.last_initial_state, open("pickle/state-%d.p" % self._pickle_state_id, "w"))

			l.debug("... deleting everything!")
			self.last_run = None
			self._entry = None
			self._project = None
		else:
			for e in self.last_run.exits():
				e.downsize()
			self.last_initial_state.downsize()

	def resume(self, project):
		'''
		Resumes the path, after unspilling.
		'''
		self._project = project

		if self.last_run is None:
			l.debug("%s resuming...", self)
			state = pickle.load(open("pickle/state-%d.p" % self._pickle_state_id))
			e = simuvex.SimExit(state=state, addr=self._pickle_addr, state_is_raw=True)
			if self._pickle_whitelist is not None or self._pickle_last_stmt is not None:
				self.continue_through_exit(e, stmt_whitelist=self._pickle_whitelist, last_stmt=self._pickle_last_stmt, copy=False)
			else:
				self.continue_through_exit(e, copy=False)

	def __repr__(self):
		return "<Path with %d runs (weight %d) (at 0x%x)>" % (0 if not hasattr(self, 'length') else self.length, self.weighted_length, 0 if self.last_addr is None else self.last_addr)

#!/usr/bin/env python

import logging
l = logging.getLogger("angr.Path")

from .errors import AngrMemoryError, AngrExitError, AngrPathError
import simuvex

import cPickle as pickle

class Path(object):
	def __init__(self, project=None, entry=None):
		# This exit is used if this path is continued with a None last_run
		self._entry = entry

		# the length of the path
		self.length = 0

		# project
		self._project = project

		# the last block that was processed
		self.last_run = None

		# this path's backtrace
		self.backtrace = [ ]
		self.addr_backtrace = [ ]

		# the refs
		self._refs = [ ]

		# these are exits that had errors
		self.errored = [ ]

		# for merging
		self.upcoming_merge_points = [ ]

		# for pickling
		self._pickle_addr = None
		self._pickle_state_id = None
		self._pickle_whitelist = None
		self._pickle_last_stmt = None

	def detect_loops(self, n):
		'''
		Returns the current loop iteration that a path is on.

		@param n: the minimum number of iterations to check for.
		@returns iteration number (>=n), or None
		'''

		# TODO: make this work better
		addr_strs = [ "%x"%x for x in self.addr_backtrace ]
		bigstr = "".join(addr_strs)

		candidates = [ ]

		max_iteration_length = len(self.addr_backtrace) / n
		for i in range(max_iteration_length):
			candidates.append("".join(addr_strs[-i-0:]))

		for c in reversed(candidates):
			if bigstr.count(c) >= n:
				return n
		return None

	def exits(self, reachable=None, symbolic=None, concrete=None):
		if self.last_run is None and self._entry is not None:
			return self._entry if self._entry is not None else [ ]
		return self.last_run.exits(reachable=reachable, symbolic=symbolic, concrete=concrete)

	def flat_exits(self, reachable=None, symbolic=None, concrete=None):
		if self.last_run is None and self._entry is not None:
			return self._entry.split() if self._entry is not None else [ ]
		return self.last_run.flat_exits(reachable=reachable, symbolic=symbolic, concrete=concrete)

	def continue_through_exit(self, e, stmt_whitelist=None, last_stmt=None, copy=True):
		try:
			new_run = self._project.sim_run(e, stmt_whitelist=stmt_whitelist, last_stmt=last_stmt)
		except (AngrExitError, AngrMemoryError, simuvex.SimIRSBError):
			l.warning("continue_through_exit() got exception at 0x%x.", e.concretize(), exc_info=True)
			self.errored.append(e)
			return None

		if copy:
			new_path = self.copy()
		else:
			new_path = self
		new_path.add_run(new_run)
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
	def add_run(self, srun):
		self.backtrace.append(str(srun))
		self.addr_backtrace.append(srun.addr)
		l.debug("Extended path with: %s", self.backtrace[-1])

		self.length += 1
		self.last_run = srun
		# NOTE: we currently don't record refs, as this causes old states
		# not to be deleted (due to the SimProcedures) and uses up TONS of memory
		#self.copy_refs(srun)

	def copy(self):
		l.debug("Copying path %s", self)
		o = Path(project=self._project)
		o.copy_refs(self)

		o.addr_backtrace = [ s for s in self.addr_backtrace ]
		o.backtrace = [ s for s in self.backtrace ]
		o.length = self.length
		o.last_run = self.last_run

		return o

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

	def merge(self, *others):
		if len(set([ o.last_addr for o in others])) != 1:
			raise AngrPathError("Unable to merge paths.")

		# merge the state
		new_state = self.last_initial_state.copy_after()
		merge_flag = new_state.merge(*[ o.last_initial_state for o in others ])
		e = simuvex.SimExit(state=new_state, addr=self.last_addr, state_is_raw=True)

		# fix the backtraces
		divergence_index = [ len(set(addrs)) == 1 for addrs in zip(*[ o.addr_backtrace for o in (others + [ self ]) ]) ].index(False)
		self.addr_backtrace = self.addr_backtrace[:divergence_index]
		self.addr_backtrace.append(-1)
		self.backtrace = self.addr_backtrace[:divergence_index]
		self.backtrace.append("MERGE POINT: %s", merge_flag)

		# continue the path
		self.continue_through_exit(e)

		# reset the upcoming merge points
		self.upcoming_merge_points = [ ]

	def suspend(self, do_pickle=True):
		'''
		Suspends the path for spilling/pickling.
		'''
		l.debug("%s suspending...", self)

		if do_pickle:
			self._pickle_state_id = id(self.last_run.initial_state)
			self._pickle_addr = self.last_run.addr
			self._pickle_whitelist = getattr(self.last_run, 'whitelist', None)
			self._pickle_last_stmt = getattr(self.last_run, 'last_stmt', None)

			l.debug("... pickling the initial state")
			pickle.dump(self.last_run.initial_state, open("pickle/state-%d.p" % self._pickle_state_id, "w"))

			l.debug("... deleting everything!")
			self.last_run = None
			self._entry = None
			self._project = None
		else:
			for e in self.last_run.exits():
				if hasattr(e.state, '_solver'):
					del e.state._solver

			if hasattr(self.last_run.initial_state, '_solver'):
				del self.last_run.initial_state._solver

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
		return "<Path with %d runs>" % (0 if not hasattr(self, 'length') else self.length)

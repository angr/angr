#!/usr/bin/env python

import logging
l = logging.getLogger("angr.Path")

from .errors import AngrMemoryError, AngrExitError
import simuvex

# unfortunately, we need to disable this because of the initialization
# pylint: disable=W0231

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
		self._refs = { r: list() for r in simuvex.RefTypes }

		# these are exits that had errors
		self.errored = [ ]

	def exits(self, reachable=None, symbolic=None, concrete=None):
		if self.last_run is None and self._entry is not None:
			return self._entry if self._entry is not None else [ ]
		return self.last_run.exits(reachable=reachable, symbolic=symbolic, concrete=concrete)

	def flat_exits(self, reachable=None, symbolic=None, concrete=None):
		if self.last_run is None and self._entry is not None:
			return self._entry.split() if self._entry is not None else [ ]
		return self.last_run.flat_exits(reachable=reachable, symbolic=symbolic, concrete=concrete)

	def continue_through_exit(self, e, stmt_whitelist=None, last_stmt=None):
		try:
			new_run = self._project.sim_run(e, stmt_whitelist=stmt_whitelist, last_stmt=last_stmt)
		except (AngrExitError, AngrMemoryError, simuvex.SimIRSBError):
			l.warning("continue_through_exit() got exception at 0x%x.", e.concretize(), exc_info=True)
			self.errored.append(e)
			return None

		new_path = self.copy()
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
		for ref_type, ref_list in other.refs().iteritems():
			self._refs[ref_type].extend(ref_list)

	# Adds a run to the path
	def add_run(self, srun):
		self.backtrace.append(str(srun))
		self.addr_backtrace.append(srun.addr)
		l.debug("Extended path with: %s", self.backtrace[-1])

		self.length += 1
		self.last_run = srun
		self.copy_refs(srun)

	def copy(self):
		l.debug("Copying path %s", self)
		o = Path(project=self._project)
		o.copy_refs(self)

		o.addr_backtrace = [ s for s in self.addr_backtrace ]
		o.backtrace = [ s for s in self.backtrace ]
		o.length = self.length
		o.last_run = self.last_run

		return o

	def __repr__(self):
		return "<Path with %d runs>" % (0 if not hasattr(self, 'length') else self.length)

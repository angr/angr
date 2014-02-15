#!/usr/bin/env python

''' This file contains support for SimSlice. '''

import logging
l = logging.getLogger("s_path")

from .s_exception import SimError
from .s_value import ConcretizingException
from .s_irsb import SimIRSBError
from .s_run import SimRun

class SimPathError(SimError):
	pass

# unfortunately, we need to disable this because of the initialization
# pylint: disable=W0231

class SimPath(SimRun):
	__slots__ = [ 'initial_exits', 'length', 'callback', 'last_run', 'backtrace' ]

	def __init__(self, callback=None, entry_exit=None):
		# This exit is used if this path is continued with a None last_run
		self.initial_exits = [ entry_exit ] if entry_exit is not None else [ ]

		# the length of the path
		self.length = 0

		# callback for creating SimRuns
		self.callback = callback

		# the last block that was processed
		self.last_run = None

		# this path's backtrace
		self.backtrace = [ ]

	# This does nothing, since we expect IRSBs to be added externally.
	def handle_run(self):
		pass

	def exits(self, reachable=None, symbolic=None, concrete=None):
		if self.last_run is None: return self.initial_exits
		return self.last_run.exits(reachable=reachable, symbolic=symbolic, concrete=concrete)

	def continue_through_exit(self, e, callback=None, stmt_whitelist=None, last_stmt=None):
		callback = callback if callback is not None else self.callback

		try:
			new_run = callback(e, options=self.options, stmt_whitelist=stmt_whitelist, last_stmt=last_stmt)
		#except ConcretizingException:
		#	l.info("Skipping unsat exit.")
		#	continue
		except SimIRSBError:
			l.warning("Skipping SimIRSBError at 0x%x.", e.concretize(), exc_info=True)
			return None

		new_path = self.copy()
		new_path.add_run(new_run)
		return new_path

	# Continues the path by sending all of the exits through the "callback" function (which must accept a SimExit and a set of options) to create new SimRuns, then branching off paths for all of them.
	def continue_path(self, callback=None, careful=True):
		callback = callback if callback is not None else self.callback

		if careful:
			exits = self.flat_exits(reachable=True)
		else:
			exits = self.flat_exits(concrete=False, reachable=True) + self.flat_exits(concrete=True)

		l.debug("Got %d exits", len(exits))

		new_paths = [ ]
		for e in exits:
			try:
				new_path = self.continue_through_exit(e, callback=callback)
				if new_path is not None:
					new_paths.append(new_path)
			except ConcretizingException:
				continue
			except Exception as e:
				# TODO: remove this hack
				if e.__class__.__name__ == "AngrException":
					continue
				else:
					raise

		l.debug("Continuing path with %d new paths.", len(new_paths))
		return new_paths

	# Adds a SimRun to the path
	def add_run(self, srun):
		self.backtrace.append(str(srun))
		l.debug("Extended path with: %s", self.backtrace[-1])

		self.length += 1
		self.last_run = srun
		self.copy_refs(srun)

	def copy(self):
		l.debug("Copying path %s", self)
		o = SimPath(self.initial_state, callback=self.callback, options=self.options)
		o.copy_refs(self)

		o.backtrace = [ s for s in self.backtrace ]
		o.length = self.length
		o.last_run = self.last_run
		o.initial_state = self.initial_state

		return o

	def __repr__(self):
		return "<SimPath with %d runs>" % self.length

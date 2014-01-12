#!/usr/bin/env python

''' This file contains support for SimSlice. '''

import logging
l = logging.getLogger("s_path")

import pyvex # pylint: disable=F0401
from .s_exception import SimError
from .s_irsb import SimIRSB
from .s_run import SimRun

class SimPathError(SimError):
	pass

# unfortunately, we need to disable this because of the initialization
# pylint: disable=W0201

class SimPath(SimRun):
	def initialize_run(self):
		# the last block that was processed
		self.last_run = None

		# has this path ever been forcefully extended with a block that would not normally be jumped to?
		self.ever_forced = False

		# this path's last block was forced (it would not normally jump to it)
		self.last_forced = False

	# This does nothing, since we expect IRSBs to be added externally.
	def handle_run(self):
		pass

	def exits(self):
		if self.last_run is None: return [ ]
		return self.last_run.exits()

	def reachable_exits(self):
		if self.last_run is None: return [ ]

		reachable_exits = [ e for e in self.exits() if e.reachable() ]
		l.debug("%d reachable exits from path:", len(reachable_exits))
		return reachable_exits

	# Adds a SimRun to the path
	def add_run(self, srun):
		self.last_run = srun
		self.copy_refs(srun)

	# Adds an IRSB to a path, returning new paths.
	def add_irsb(self, irsb, path_limit = 255, force = False):
		new_paths = [ ]
		first_imark = [ i for i in irsb.statements() if type(i) == pyvex.IRStmt.IMark ][0]

		if self.last_run is None:
			new_sirsb = SimIRSB(self.initial_state, irsb, options=self.options)
			new_path = self.copy()
			new_path.add_run(new_sirsb)
			new_paths.append(new_path)

			l.debug("First block in path!")
		else:
			exits = self.reachable_exits()
			if len(exits) == 0:
				l.warning("No reachable exits from path.")
				return [ ]

			relevant_exits = [ ]
			irrelevant_exits = [ ]
			for e in exits:
				if e.sim_value.is_solution(first_imark.addr): relevant_exits.append(e)
				else: irrelevant_exits.append(e)

			l.debug("%d relevant and %d irrelevant exits", len(relevant_exits), len(irrelevant_exits))
			# if there are no feasible solutions (which can happen if we're skipping instructions), use the unfeasible states
			followed_exits = relevant_exits[:path_limit]
			this_forced = False

			if len(followed_exits) == 0 and force:
				followed_exits = irrelevant_exits
				this_forced = True

			for e in followed_exits:
				# TODO: add IP updating to state
				new_sirsb = SimIRSB(e.state, irsb, options=self.options)
				new_path = self.copy()
				new_path.last_forced = this_forced
				new_path.ever_forced |= this_forced
				new_path.add_run(new_sirsb)
				new_paths.append(new_path)

		return new_paths


	def copy(self):
		l.debug("Copying path")
		o = SimPath(self.initial_state, options=self.options)
		o.copy_refs(self)

		o.last_run = self.last_run
		o.initial_state = self.initial_state
		o.ever_forced = self.ever_forced
		o.last_forced = self.last_forced

		return o

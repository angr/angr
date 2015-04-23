#!/usr/bin/env python

from ..surveyor import Surveyor
from . import Explorer

import logging
l = logging.getLogger("angr.surveyors.Escaper")

class Escaper(Surveyor):
	'''
	Escaper implements loop escaping!

		normal - any found normal paths from the loop
		forced - forced paths from the loop, if a normal wasn't found
	'''

	def __init__(self, project, loop_addresses, start=None, max_concurrency=None, max_active=None, pickle_paths=None, loop_iterations=0, iteration_depth=100, unconstrain_memory=True, unconstrain_registers=True):
		'''
		Creates an Escaper. Most options are for Surveyor (separate docs).

		@param loop_addresses: the addresses of all the basic blocks in the loop, to know the
							   instructions to which the analysis should be restricted
		@param loop_iterations: the number of times to run the loop before escaping
		@param iteration_depth: the maximum depth (in SimRuns) of a path through the loop
		'''
		Surveyor.__init__(self, project, start=start, max_concurrency=max_concurrency, max_active=max_active, pickle_paths=pickle_paths)

		self._loop_addresses = loop_addresses
		self._loop_iterations = loop_iterations
		self._iteration_depth = iteration_depth
		self._current_iteration = 0
		self._done = False

		self._unconstrain_memory = unconstrain_memory
		self._unconstrain_registers = unconstrain_registers

		self.normal = [ ]
		self.forced = [ ]

	def _tick_loop(self, start=None):
		results = Explorer(self._project, start=start, find=self._loop_addresses[0], restrict=self._loop_addresses, min_depth=2, max_depth=self._iteration_depth, max_repeats=1, max_concurrency=self._max_concurrency, num_find=self._num_find).run()

		self.deadended += results.deadended
		return results

	def unconstrain_loop(self, constrained_entry):
		'''
		Unconstrains an exit to the loop header by looping one more time
		and replacing all modified variables with unconstrained versions.
		'''

		constrained_state = constrained_entry.state.copy()

		# first, go through the loop normally, one more time
		constrained_results = self._tick_loop(start=constrained_entry)
		l.debug("%d paths to header found", len(constrained_results.found))

		# then unconstrain differences between the original state and any new
		# head states
		unconstrained_states = []
		for p in constrained_results.found:
			# because the head_entry might actually point partway *through* the
			# loop header, in the cases of a loop starting between
			# the counter-increment and the condition check (because the
			# counter is only incremented at the end of the loop, and the
			# end is placed in the beginning for optimization), so we run the
			# loop through to the *end* of the header
			new_state = p.state.copy()
			if self._unconstrain_registers:
				new_state.registers.unconstrain_differences(constrained_state.registers)
			if self._unconstrain_memory:
				new_state.memory.unconstrain_differences(constrained_state.memory)

			unconstrained_states.append(new_state)
		l.debug("%d unconstrained states", len(unconstrained_states))

		unconstrained_exits = []
		unconstrained_entry = constrained_entry
		for s in unconstrained_states:
			unconstrained_entry.state = s
			unconstrained_results = self._tick_loop(start=unconstrained_entry)

			unconstrained_exits += unconstrained_results.deviating

		return unconstrained_exits

	def tick(self):
		'''
		Makes one run through the loop.
		'''
		if self._current_iteration < self._loop_iterations:
			l.debug("Currently at iteration %d of %d", self._current_iteration, self._loop_iterations)

			results = self._tick_loop(start=self.active_exits(reachable=True))

			l.debug("... found %d exiting paths", len(results.deviating))
			self.normal += results.deviating
			self.active = results.found

			self._current_iteration += 1
		else:
			all_exits = self.active_exits(reachable=True)
			l.debug("Unconstraining %d heads.", len(all_exits))
			for e in all_exits:
				self.forced += self.unconstrain_loop(e)

			self._done = True

	@property
	def done(self):
		return self._done

	def __repr__(self):
		return "<Escaper with paths: %s, %d normal, %d forced>" % (Surveyor.__repr__(self), len(self.normal), len(self.forced))

from . import all_surveyors
all_surveyors['Escaper'] = Escaper

#!/usr/bin/env python

import simuvex
from angr import Surveyor
from . import Explorer

import collections
import logging
l = logging.getLogger("angr.surveyors.Escaper")

class Escaper(Surveyor):
	'''
	Escaper implements loop escaping!

		normal - any found normal paths from the loop
		forced - forced paths from the loop, if a normal wasn't found
	'''

	def __init__(self, project, addresses, start=None, starts=None, max_concurrency=None, mode=None, options=None, loop_iterations=0, iteration_depth=100):
		'''
		Creates an Escaper.

		@param project: the angr.Project to analyze
		@param start: a single exit to start the analysis on
		@param starts: the exits to start the analysis on. If neither this nor start are given,
					   the analysis starts from p.initial_exit()
		@param max_concurrency: the maximum number of paths to explore at a time

		@param addresses: the addresses of all the basic blocks in the loop, to know the
							   instructions to which the analysis should be restricted
		@param loop_iterations: the number of times to run the loop before escaping
		@param iteration_depth: the maximum depth (in SimRuns) of a path through the loop
		'''
		Surveyor.__init__(self, project, start=start, starts=starts, max_concurrency=max_concurrency, mode=mode, options=options)

		self._loop_addresses = addresses
		self._loop_iterations = loop_iterations
		self._iteration_depth = iteration_depth
		self._current_iteration = 0
		self.done = False

		self.normal = [ ]
		self.forced = [ ]

	@property
	def done(self):
		pass

	def tick(self):
		'''
		Makes one run through the loop.
		'''
		l.debug("Currently at iteration %d of %d", self._current_iteration, self._loop_iterations)

		current_heads = self.active_exits()
		results = Explorer(starts=current_heads, find=self._loop_addresses, max_depth=self._iteration_depth, max_repeats=1).run()

		l.debug("... found %d exiting paths", len(results.deviating))
		self.normal += results.deviating
		self.active = results.found

		Surveyor.tick(self)
		self._current_depth += 1

		# just do this for now if we're below the limit
		if self._current_depth < self._min_depth:
			return self

		# now split the paths out
		still_active = []
		for p in self.active:
			if isinstance(p.last_run, simuvex.SimIRSB):
				imark_set = set(p.last_run.imark_addrs())
			else:
				imark_set = { p.last_run.addr }

			for addr in imark_set:
				self._instruction_counter[addr] += 1

			find_intersection = imark_set & self._find
			avoid_intersection = imark_set & self._avoid
			restrict_intersection = imark_set & self._restrict

			if len(avoid_intersection) > 0:
				l.debug("Avoiding path %s due to matched avoid addresses: %s", p, avoid_intersection)
				self.avoided.append(p)
			elif len(find_intersection) > 0:
				l.debug("Marking path %s as found due to matched target addresses: %s", p, [ "0x%x" % _ for _ in find_intersection ])
				self.found.append(p)
			elif len(self._restrict) > 0 and len(restrict_intersection) == 0:
				l.debug("Path %s is not on the restricted addresses!", p)
				self.deviating.append(p)
			elif collections.Counter(p.backtrace).most_common(1)[0][1] > self._max_repeats:
				# discard any paths that loop too much
				l.debug("Path %s appears to be looping!", p)
				self.looping.append(p)
			else:
				still_active.append(p)

			self.active = still_active

	def trim(self):
		# if there are too many paths, prioritize the ones that are
		# executing less-commonly-seen instructions
		if len(self.active) > self._max_concurrency:
			# first, filter them down to only the satisfiable ones
			l.debug("Trimming %d paths to avoid a state explosion.", len(self.active) - self._max_concurrency)
			self.active.sort(cmp=self.path_comparator)
			self.trimmed += self.active[self._max_concurrency:]
			self.active = self.active[:self._max_concurrency]

	def report(self):
		return "%d found, %d avoided, %d deviating, %d looping" % (len(self.found), len(self.avoided), len(self.deviating), len(self.looping))

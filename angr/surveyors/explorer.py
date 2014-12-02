#!/usr/bin/env python

import simuvex
from ..surveyor import Surveyor

import collections
import networkx
import logging
l = logging.getLogger("angr.surveyors.Explorer")

class Explorer(Surveyor):
	'''
	Explorer implements a symbolic exploration engine!

		found - paths where the target addresses have been found
		avoided - paths where the to-avoid addresses have been found
		deviating - paths that deviate from the restricted-to addresses
		looping - paths that were detected as looping
	'''

	path_lists = Surveyor.path_lists + [ 'found', 'avoided', 'deviating', 'looping']

	def __init__(self, project, start=None, starts=None, max_concurrency=None, max_active=None, pickle_paths=None, find=(), avoid=(), restrict=(), min_depth=0, max_depth=None, max_repeats=10000000, num_find=1, num_avoid=None, num_deviate=1, num_loop=None, cut_lost=None):
		'''
		Explores the path space until a block containing a specified address is
		found. Parameters (other than for Surveyor):

		@param find: a tuple containing the addresses to search for
		@param avoid: a tuple containing the addresses to avoid
		@param restrict: a tuple containing the addresses to restrict the
						 analysis to (i.e., avoid all others)
		@param min_depth: the minimum number of SimRuns in the resulting path
		@param max_depth: the maximum number of SimRuns in the resulting path

		@param num_find: the minimum number of paths to find (default: 1)
		@param num_avoid: the minimum number of paths to avoid
						  (default: infinite)
		@param num_deviate: the minimum number of paths to deviate
							(default: infinite)
		@param num_loop: the minimum number of paths to loop
						 (default: infinite)
		@param cut_lost: cut any paths that have no chance of going to the target
		'''
		Surveyor.__init__(self, project, start=start, starts=starts, max_concurrency=max_concurrency, max_active=max_active, pickle_paths=pickle_paths)

		# initialize the counter
		self._instruction_counter = collections.Counter()

		self._find = self._arg_to_set(find)
		self._avoid = self._arg_to_set(avoid)
		self._restrict = self._arg_to_set(restrict)
		self._max_repeats = max_repeats
		self._max_depth = max_depth
		self._min_depth = min_depth

		self.found = [ ]
		self.avoided = [ ]
		self.deviating = [ ]
		self.looping = [ ]
		self.lost = [ ]

		self._num_find = num_find
		self._num_avoid = num_avoid
		self._num_deviate = num_deviate
		self._num_loop = num_loop

		self._cut_lost = len(self._find) == 0 and self._project._cfg is not None if cut_lost is None else cut_lost

		if self._cut_lost and self._project._cfg is None:
			raise AngrSurveyorError("cut_lost requires a CFG")
		if self._cut_lost:
			good_find = set()
			for f in self._find:
				if self._project._cfg.get_any_irsb(f) is None:
					l.warning("No node 0x%x in CFG. This will be automatically cut.", f)
				else:
					good_find.add(f)
			self._find = good_find

	@property
	def _f(self):
		return self.found[0]

	@property
	def _av(self):
		return self.avoided[0]

	@property
	def _dv(self):
		return self.deviating[0]

	@property
	def _lo(self):
		return self.looping[0]

	@staticmethod
	def _arg_to_set(s):
		if type(s) in (int, long): return { s }
		return set(s)

	def path_comparator(self, x, y):
		return self._instruction_counter[x.last_addr] - self._instruction_counter[y.last_addr]

	@property
	def done(self):
		if len(self.active) == 0:
			l.debug("Done because we have no active paths left!")
			return True

		if self._num_find is not None and len(self.found) >= self._num_find:
			l.debug("Done because we found the targets on %d path(s)!", len(self.found))
			return True

		if self._num_avoid is not None and len(self.avoided) >= self._num_avoid:
			l.debug("Done because we avoided on %d path(s)!", len(self.avoided))
			return True

		if self._num_deviate is not None and len(self.deviating) >= self._num_deviate:
			l.debug("Done because we deviated on %d path(s)!", len(self.deviating))
			return True

		if self._num_loop is not None and len(self.looping) >= self._num_loop:
			l.debug("Done because we looped on %d path(s)!", len(self.looping))
			return True

		return False

	def filter_path(self, p):
		if self._cut_lost and not isinstance(p.last_run, simuvex.SimProcedure):
			f = self._project._cfg.get_any_irsb(p.last_run.addr)
			if f is None:
				l.warning("CFG has no node at 0x%x. Cutting this path.", p.last_run.addr)
				return False
			if not any(((networkx.has_path(self._project._cfg._graph, f, self._project._cfg.get_any_irsb(t)) for t in self._find))):
				l.debug("Cutting path %s because it's lost.", p)
				self.lost.append(p)
				return False

		if len(p.addr_backtrace) < self._min_depth:
			return True

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
			return False
		elif len(find_intersection) > 0:
			l.debug("Marking path %s as found due to matched target addresses: %s", p, [ "0x%x" % _ for _ in find_intersection ])
			self.found.append(p)
			return False
		elif len(self._restrict) > 0 and len(restrict_intersection) == 0:
			l.debug("Path %s is not on the restricted addresses!", p)
			self.deviating.append(p)
			return False
		elif p.detect_loops(self._max_repeats) >= self._max_repeats:
			# discard any paths that loop too much
			l.debug("Path %s appears to be looping!", p)
			self.looping.append(p)
			return False
		elif self._max_depth is not None and len(p.backtrace) > self._max_depth:
			l.debug('Path %s exceeds the maximum depth(%d) allowed.', p, self._max_depth)
			return False
		else:
			return True

	def __repr__(self):
		return "<Explorer with paths: %s, %d found, %d avoided, %d deviating, %d looping, %d lost>" % (Surveyor.__repr__(self), len(self.found), len(self.avoided), len(self.deviating), len(self.looping), len(self.lost))

from ..errors import AngrSurveyorError

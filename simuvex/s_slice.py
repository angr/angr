#!/usr/bin/env python

''' This file contains support for SimSlice. '''

import logging
l = logging.getLogger("s_slice")

from .s_exception import SimError
from .s_path import SimPath

class SimSliceError(SimError):
	pass

class SimSlice(object):
	'''SimSlice adds support for program slicing. Given an annotated graph of the edges to follow and statements to call, it follows all paths through the graph.'''

	def __init__(self, initial_exit, annotated_cfg, callback, mode=None, options=None):
		l.debug("Creating slice!")

		# these paths have hit a "do not follow" or an unsat exit
		self.final_paths = [ ]

		# the callback function for making SimRuns
		self.callback = callback

		# save options and stuff
		self.mode = mode
		self.options = options
		self.annotated_cfg = annotated_cfg

		# these paths are still being analyzed
		initial_target = initial_exit.concretize()
		whitelist = self.annotated_cfg.get_whitelisted_statements(initial_target)
		l.debug("Initial target 0x%x has %d whitelisted statements.", initial_target, len(whitelist))
		whitelist = None
		start_path = SimPath(initial_exit.state, callback=callback, mode=mode, options=options).continue_through_exit(initial_exit, stmt_whitelist=whitelist)
		self.paths = [ start_path ]

		self.exhaust_cfg()

	def exhaust_cfg(self):
		while len(self.paths) != 0:
			l.debug("Following %d remaining paths...", len(self.paths))
			self.follow_all_paths()

	def follow_all_paths(self):
		new_paths = [ ]
		for p in self.paths:
			continuations = self.follow_path(p)
			if len(continuations) == 0:
				l.debug("Path %s is final.", p)
				self.final_paths.append(p)
			else:
				l.debug("Continuing path with %d continuations.", len(continuations))
				new_paths.extend(continuations)
		self.paths = new_paths

	def follow_path(self, path):
		path_exits = path.flat_exits(reachable=True)
		new_paths = [ ]

		for e in path_exits:
			dst_addr = e.concretize()
			taken = self.annotated_cfg.should_take_exit(path.last_run.addr, dst_addr)
			l.debug("should_take_exit returned %s for 0x%x (%s) -> 0x%x", taken, path.last_run.addr, path.last_run.__class__.__name__, dst_addr)
			if taken:
				whitelist = self.annotated_cfg.get_whitelisted_statements(dst_addr)
				whitelist = None
				new_paths.append(path.continue_through_exit(e, stmt_whitelist=whitelist))

		return new_paths

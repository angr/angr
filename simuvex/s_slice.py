#!/usr/bin/env python

''' This file contains support for SimSlice. '''

import logging
l = logging.getLogger("s_slice")

from .s_exception import SimError
from .s_path import SimPath
from .s_irsb import SimIRSB
from .s_procedure import SimProcedure

class SimSliceError(SimError):
	pass

class SimSlice(object):
	'''SimSlice adds support for program slicing. Given an annotated graph of the edges to follow and statements to call, it follows all paths through the graph.'''

	def __init__(self, initial_exit, annotated_cfg, callback, mode=None, options=None):
		# these paths have hit a "do not follow" or an unsat exit
		self.final_paths = [ ]

		# these paths are still being analyzed
		self.paths = [ SimPath(initial_exit.state, entry_exit=initial_exit, callback=callback, mode=mode, options=options) ]

		# the callback function for making SimRuns
		self.callback = callback

		# save options and stuff
		self.mode = mode
		self.options = options
		self.annotated_cfg = annotated_cfg

		self.exhaust_cfg()

	def exhaust_cfg(self):
		while len(self.paths) != 0:
			self.follow_all_paths()

	def follow_all_paths(self):
		new_paths = [ ]
		for p in self.paths:
			continuations = self.follow_path(p)
			if len(continuations) == 0:
				self.final_paths.append(p)
			else:
				new_paths.extend(continuations)
		self.paths = new_paths

	def follow_path(self, path):
		path_exits = path.flat_exits(reachable=True)
		new_paths = [ ]

		for e in path_exits:
			if isinstance(path.last_run, SimIRSB):
				src_addr = path.last_run.first_imark.addr
			elif isinstance(path.last_run, SimProcedure):
				src_addr = path.last_run.addr_from

			dst_addr = e.concretize()
			if self.annotated_cfg.should_take_exit(src_addr, dst_addr):
				whitelist = self.annotated_cfg.get_whitelisted_statements(dst_addr)
				new_paths.append(path.continue_through_exit(e, stmt_whitelist=whitelist))

		return new_paths

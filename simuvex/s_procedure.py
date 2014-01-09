#!/usr/bin/env python

from .s_run import SimRun
import itertools

import logging
l = logging.getLogger(name = "s_absfunc")

symbolic_count = itertools.count()

class SimProcedure(SimRun):
	def __init__(self, state, procedure_id=None, options=None, mode=None):
		SimRun.__init__(self, options=options, mode=mode)
		self.id = procedure_id
		self.initial_state = state.copy_after()
		self.addr_from = -1

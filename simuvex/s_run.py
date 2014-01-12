#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.s_run")

from .s_ref import RefTypes
import s_options as o

class SimRun(object):
	def __init__(self, *args, **kwargs):
		state = args[0]
		options = None
		mode = None

		if 'options' in kwargs:
			options = kwargs['options']
			del kwargs['options']

		if 'mode' in kwargs:
			mode = kwargs['mode']
			del kwargs['mode']

		# the options and mode
		if options is None:
			options = o.default_options[mode]
		self.options = options
		self.mode = mode
		self.initial_state = state
		self.state = self.initial_state.copy_after()

		# Intitialize the exits and refs
		self._exits = [ ]
		self._refs = { }
		self.options = options
		for t in RefTypes:
			self._refs[t] = [ ]

		l.debug("SimRun created with %d constraints.", len(self.initial_state.constraints_after()))
		self.initialize_run(*(args[1:]), **kwargs)
		self.handle_run()
		l.debug("Ending SimRun with %d constraints.", len(self.state.old_constraints))

	def initialize_run(self, *args, **kwargs):
		pass

	def handle_run(self):
		raise Exception("SimRun.handle_run() has been called. This should have been overwritten in class %s.", self.__class__)

	def refs(self):
		return self._refs

	def exits(self):
		return self._exits

	# Categorize and add a sequence of refs to this run
	def add_refs(self, *refs):
		for r in refs:
			if o.SYMBOLIC not in self.options and r.is_symbolic():
				continue

			self._refs[type(r)].append(r)

	# Categorize and add a sequence of exits to this run
	def add_exits(self, *exits):
		for e in exits:
			if o.SYMBOLIC not in self.options and e.sim_value.is_symbolic():
				continue

			self._exits.append(e)

	# Copy the references
	def copy_refs(self, other):
		for ref_list in other.refs().itervalues():
			self.add_refs(*ref_list)

	# Copy the exits
	def copy_exits(self, other):
		self.add_exits(*other.exits())

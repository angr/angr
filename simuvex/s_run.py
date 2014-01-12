#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.s_run")

from .s_ref import RefTypes
import s_options as o

class SimRunMeta(type):
	def __call__(mcs, *args, **kwargs):
		c = mcs.make_run(args, kwargs)
		c.__init__(*args[1:], **kwargs)
		return c

	def get_and_remove(mcs, kwargs, what, default=None):
		mcs = mcs #shut up pylint
		if what in kwargs:
			v = kwargs[what]
			del kwargs[what]
			return v
		else:
			return default

	def make_run(mcs, args, kwargs):
		state = args[0]
		options = mcs.get_and_remove(kwargs, 'options')
		mode = mcs.get_and_remove(kwargs, 'mode')

		c = mcs.__new__(mcs)
		SimRun.__init__(c, state, options=options, mode=mode)
		return c

class SimRun(object):
	__metaclass__ = SimRunMeta

	def __init__(self, state, options=None, mode=None):
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
		#self.initialize_run(*(args[1:]), **kwargs)
		#self.handle_run()
		l.debug("Ending SimRun with %d constraints.", len(self.state.old_constraints))

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

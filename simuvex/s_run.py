#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.s_run")

from .s_ref import RefTypes
import s_options as o
import s_helpers

class SimRunMeta(type):
	def __call__(mcs, *args, **kwargs):
		c = mcs.make_run(args, kwargs)
		if not hasattr(c.__init__, 'flagged'):
			c.__init__(*args[1:], **kwargs)
		return c

	def make_run(mcs, args, kwargs):
		state = args[0]
		options = s_helpers.get_and_remove(kwargs, 'options')
		mode = s_helpers.get_and_remove(kwargs, 'mode')

		c = mcs.__new__(mcs)
		SimRun.__init__(c, state, options=options, mode=mode)
		return c

class SimRun(object):
	__metaclass__ = SimRunMeta

	@s_helpers.flagged
	def __init__(self, state, options=None, mode=None):
		# the options and mode
		if options is None:
			options = o.default_options[mode if mode is not None else "static"]
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

	def exits(self, reachable=None):
		if reachable is not None:
			reachable_exits = [ e for e in self._exits if e.reachable() == reachable ]
			l.debug("Returning %d out of %d exits for reachable=%s", len(reachable_exits), len(self._exits), reachable)
			return reachable_exits
		return self._exits

	def flat_exits(self, reachable=None):
		all_exits = [ ]
		for e in self.exits():
			all_exits.extend(e.split())

		if reachable is not None:
			reachable_exits = [ e for e in all_exits if e.reachable() == reachable ]
			l.debug("Returning %d out of %d flat exits for reachable=%s", len(reachable_exits), len(all_exits), reachable)
			return reachable_exits
		return all_exits

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

	# Copy the exits and references of a run.
	def copy_run(self, other):
		self.copy_refs(other)
		self.copy_exits(other)

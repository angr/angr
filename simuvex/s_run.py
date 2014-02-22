#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.s_run")

from .s_ref import RefTypes
import s_options as o
import s_helpers
import s_exit

class SimRunMeta(type):
	def __call__(mcs, *args, **kwargs):
		c = mcs.make_run(args, kwargs)
		if not hasattr(c.__init__, 'flagged'):
			c.__init__(*args[1:], **kwargs)

			# now delete the final state; it should be exported in exits
			if hasattr(c, 'state'):
				delattr(c, 'state')
		return c

	def make_run(mcs, args, kwargs):
		state = args[0]
		addr = s_helpers.get_and_remove(kwargs, 'addr')
		inline = s_helpers.get_and_remove(kwargs, 'inline')

		c = mcs.__new__(mcs)
		SimRun.__init__(c, state, addr=addr, inline=inline)
		return c

class SimRun(object):
	__metaclass__ = SimRunMeta
	__slots__ = [ 'addr', '_inline', 'initial_state', 'state', '_exits', '_refs' ]

	@s_helpers.flagged
	def __init__(self, state, addr=None, inline=False):
		# The address of this SimRun
		self.addr = addr

		# state stuff
		self.initial_state = state
		self._inline = inline
		if not self._inline:
			self.state = self.initial_state.copy_after()
		else:
			self.state = self.initial_state

		# Intitialize the exits and refs
		self._exits = [ ]
		self._refs = [ ]

		l.debug("%s created with %d constraints.", self, len(self.initial_state.constraints_after()))

	def refs(self):
		return self._refs

	def exits(self, reachable=None, symbolic=None, concrete=None):
		concrete = True if concrete is None else concrete

		symbolic_exits = [ ]
		concrete_exits = [ ]
		for e in self._exits:
			symbolic = o.SYMBOLIC in e.state.options if symbolic is None else symbolic

			if e.sim_value.is_symbolic() and symbolic:
				symbolic_exits.append(e)
			elif concrete:
				concrete_exits.append(e)

		s_exit.l.debug("Starting exits() with %d exits", len(self._exits))
		s_exit.l.debug("... considering: %d symbolic and %d concrete", len(symbolic_exits), len(concrete_exits))

		if reachable is not None:
			symbolic_exits = [ e for e in symbolic_exits if e.reachable() == reachable ]
			concrete_exits = [ e for e in concrete_exits if e.reachable() == reachable ]
			s_exit.l.debug("... reachable: %d symbolic and %d concrete", len(symbolic_exits), len(concrete_exits))

		return symbolic_exits + concrete_exits

	def flat_exits(self, reachable=None, symbolic=None, concrete=None):
		all_exits = [ ]
		for e in self.exits(reachable=reachable, symbolic=symbolic, concrete=concrete):
			all_exits.extend(e.split())

		return all_exits

	# Categorize and add a sequence of refs to this run
	def add_refs(self, *refs):
		for r in refs:
			if o.SYMBOLIC not in self.initial_state.options and r.is_symbolic():
				continue

			self._refs.append(r)

	# Categorize and add a sequence of exits to this run
	def add_exits(self, *exits):
		self._exits.extend(exits)

	# Copy the references
	def copy_refs(self, other):
		self.add_refs(*other.refs())

	# Copy the exits
	def copy_exits(self, other):
		self.add_exits(*other.exits())

	# Copy the exits and references of a run.
	def copy_run(self, other):
		self.copy_refs(other)
		self.copy_exits(other)

	def __repr__(self):
		return "<SimRun (%s) with addr %s>" % (self.__class__.__name__, "0x%x" % self.addr if self.addr is not None else "None")

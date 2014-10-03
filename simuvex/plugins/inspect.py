# TODO: SimValue being able to compare two symbolics for is_solution

import logging
l = logging.getLogger("simuvex.s_inspect")

event_types = { 'mem_read', 'mem_write', 'reg_read', 'reg_write', 'tmp_read', 'tmp_write', 'expr', 'statement', 'instruction', 'irsb', 'constraints', 'exit', 'symbolic_variable' }
inspect_attributes = {
	'mem_read_address',
	'mem_read_expr',
	'mem_read_length',

	'mem_write_address',
	'mem_write_expr',
	'mem_write_length',

	'reg_read_offset',
	'reg_read_expr',
	'reg_read_length',

	'reg_write_offset',
	'reg_write_expr',
	'reg_write_length',

	'tmp_read_num',
	'tmp_read_expr',

	'tmp_write_num',
	'tmp_write_expr',

	'expr',
	'statement',
	'instruction',
	'address',
	'added_constraints',

	'exit_target',
	'exit_guard',
	'backtrace',

	'symbolic_name',
	'symbolic_size',
	'symbolic_expr',
	}

BP_BEFORE = 'before'
BP_AFTER = 'after'

class BP(object):
	def __init__(self, when=BP_BEFORE, enabled=None, condition=None, action=None, **kwargs):
		if len(set([ k.replace("_unique", "") for k in kwargs.keys()]) - set(inspect_attributes)) != 0:
			raise ValueError("Invalid inspect attribute(s) %s passed in. Should be one of %s, or their _unique option." % (kwargs, inspect_attributes))

		self.kwargs = kwargs

		self.enabled = True if enabled is None else enabled
		self.condition = condition
		self.action = action
		self.when = when

	def check(self, state, when):
		ok = self.enabled and when == self.when
		l.debug("... after enabled and when: %s", ok)

		for a in [ _ for _ in self.kwargs.keys() if not _.endswith("_unique") ]:
			current_expr = getattr(state.inspect, a)
			needed = self.kwargs.get(a, None)

			l.debug("... checking condition %s", a)

			if current_expr is None and needed is None:
				l.debug("...... both None, True")
				c_ok = True
			elif current_expr is not None and needed is not None:
				if state.se.solution(current_expr, needed):
					l.debug("...... is_solution!")
					c_ok = True
				else:
					l.debug("...... not solution...")
					c_ok = False

				if c_ok and self.kwargs.get(a+'_unique', True):
					l.debug("...... checking uniqueness")
					if not state.se.unique(current_expr):
						l.debug("...... not unique")
						c_ok = False
			else:
				l.debug("...... one None, False")
				c_ok = False

			ok = ok and c_ok
			l.debug("... after condition %s: %s", a, ok)

		ok = ok and (self.condition is None or self.condition(state))
		l.debug("... after condition func: %s", ok)
		return ok

	def fire(self, state):
		if self.action is None:
			import ipdb; ipdb.set_trace() #pylint:disable=F0401
		else:
			self.action(state)

	def __repr__(self):
		return "<BP %s-action with conditions %r, %s condition func, %s action func>" % (self.when, self.kwargs, "no" if self.condition is None else "with", "no" if self.action is None else "with")

from .plugin import SimStatePlugin

class SimInspector(SimStatePlugin):
	def __init__(self):
		SimStatePlugin.__init__(self)
		self._breakpoints = { }
		for t in event_types:
			self._breakpoints[t] = [ ]

		for i in inspect_attributes:
			setattr(self, i, None)

	def action(self, event_type, when, **kwargs):
		l.debug("Event %s (%s) firing...", event_type, when)
		for k,v in kwargs.iteritems():
			if k not in inspect_attributes:
				raise ValueError("Invalid inspect attribute %s passed in. Should be one of: %s" % (k, event_types))
			#l.debug("... %s = %r", k, v)
			l.debug("... setting %s", k)
			setattr(self, k, v)

		for bp in self._breakpoints[event_type]:
			l.debug("... checking bp %r", bp)
			if bp.check(self.state, when):
				l.debug("... FIRE")
				bp.fire(self.state)

	def add_breakpoint(self, event_type, bp):
		if event_type not in event_types:
			raise ValueError("Invalid event type %s passed in. Should be one of: %s" % (event_type, event_types))
		self._breakpoints[event_type].append(bp)

	def remove_breakpoint(self, event_type, bp):
		self._breakpoints[event_type].remove(bp)

	def copy(self):
		c = SimInspector()
		for i in inspect_attributes:
			setattr(c, i, getattr(self, i))

		for t,a in self._breakpoints.iteritems():
			c._breakpoints[t].extend(a)
		return c

	def merge(self, others, merge_flag, merge_values): # pylint: disable=unused-argument
		for t in event_types:
			seen = { id(e) for e in self._breakpoints[t] }
			for o in others:
				for b in o._breakpoints[t]:
					if id(b) not in seen:
						self._breakpoints[t].append(b)
						seen.add(id(b))
		return [ ]

SimInspector.register_default('inspector', SimInspector)

#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.plugins.log")

import sys
import itertools

from .plugin import SimStatePlugin
class SimStateLog(SimStatePlugin):
	def __init__(self, old_events=None):
		SimStatePlugin.__init__(self)
		self.new_events = [ ]
		self.old_events = [ ] if old_events is None else old_events

	def add_event(self, event_type, **kwargs):
		try:
			new_event = SimEvent(self.state, event_type, **kwargs)
			self.new_events.append(new_event)
		except TypeError:
			e_type, value, traceback = sys.exc_info()
			raise SimEventError, ("Exception when logging event:", e_type, value), traceback

	def _add_event(self, event):
		self.new_events.append(event)

	def events_of_type(self, event_type):
		return [ e for e in itertools.chain(self.new_events, self.old_events) if e.type == event_type ]

	def copy(self):
		return SimStateLog(old_events=self.old_events + self.new_events)

	def merge(self, others, flag, flag_values): #pylint:disable=unused-argument
		all_events = [ e.old_events + e.new_events for e in itertools.chain([self], others) ]
		self.new_events = [ ]
		self.old_events = [ SimEvent(self.state, 'merge', event_lists=all_events) ]
		return False, [ ]

from ..s_errors import SimEventError
from ..s_event import SimEvent
SimStateLog.register_default('log', SimStateLog)

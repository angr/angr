#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.plugins.log")

import sys
import itertools

from .plugin import SimStatePlugin
class SimStateLog(SimStatePlugin):
    def __init__(self, log=None):
        SimStatePlugin.__init__(self)

        # general events
        self.events = [ ]

        if log is not None:
            self.events.extend(log.events)

    @property
    def actions(self):
        for e in self.events:
            if isinstance(e, SimAction):
                yield e

    def add_event(self, event_type, **kwargs):
        try:
            new_event = SimEvent(self.state, event_type, **kwargs)
            self.events.append(new_event)
        except TypeError:
            e_type, value, traceback = sys.exc_info()
            raise SimEventError, ("Exception when logging event:", e_type, value), traceback

    def _add_event(self, event):
        self.events.append(event)

    def add_action(self, action):
        self.events.append(action)

    def extend_actions(self, new_actions):
        self.events.extend(new_actions)

    def events_of_type(self, event_type):
        return [ e for e in self.events if e.type == event_type ]

    def actions_of_type(self, action_type):
        return [ action for action in self.actions if action.type == action_type ]

    def copy(self):
        return SimStateLog(log=self)

    def _combine(self, others):
        all_events = [ e.events for e in itertools.chain([self], others) ]
        self.events = [ SimEvent(self.state, 'merge', event_lists=all_events) ]
        return False

    def merge(self, others, merge_conditions):
        return self._combine(others)

    def widen(self, others):
        return self._combine(others)

    def clear(self):
        s = self.state
        self.__init__()
        self.state = s
        #self.events = [ ]
        #self.temps.clear()
        #self.used_variables.clear()
        #self.input_variables.clear()

from ..s_errors import SimEventError
from ..s_event import SimEvent
from ..s_action import SimAction
SimStateLog.register_default('log', SimStateLog)

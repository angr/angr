#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.plugins.log")

import sys
import itertools

from .plugin import SimStatePlugin
class SimStateLog(SimStatePlugin):
    def __init__(self, log=None):
        SimStatePlugin.__init__(self)
        self.events = [ ]
        self.actions = [ ]
        self.jumpkind = None
        self.guard = None
        self.target = None
        self.source = None

        if log is not None:
            self.events.extend(log.events)
            self.actions.extend(log.actions)
            self.jumpkind = log.jumpkind
            self.guard = log.guard
            self.target = log.target
            self.source = log.source

    def add_event(self, event_type, **kwargs):
        try:
            new_event = SimEvent(self.state, event_type, **kwargs)
            self.events.append(new_event)
        except TypeError:
            e_type, value, traceback = sys.exc_info()
            raise SimEventError, ("Exception when logging event:", e_type, value), traceback

    def _add_event(self, event):
        self.events.append(event)

    def _add_action(self, action):
        self.actions.append(action)

    def extend_actions(self, new_actions):
        self.actions.extend(new_actions)

    def events_of_type(self, event_type):
        return [ e for e in self.events if e.type == event_type ]

    def actions_of_type(self, action_type):
        return [ action for action in self.actions if action.type == action_type ]

    def copy(self):
        return SimStateLog(log=self)

    def merge(self, others, flag, flag_values): #pylint:disable=unused-argument
        all_events = [ e.events for e in itertools.chain([self], others) ]
        self.events = [ SimEvent(self.state, 'merge', event_lists=all_events) ]
        all_actions = [ a.actions for a in itertools.chain([self], others) ]
        self.actions = [ SimEvent(self.state, 'merge', event_lists=all_actions) ]
        return False, [ ]

    def clear(self):
        self.events = [ ]
        self.actions = [ ]

from ..s_errors import SimEventError
from ..s_event import SimEvent
SimStateLog.register_default('log', SimStateLog)

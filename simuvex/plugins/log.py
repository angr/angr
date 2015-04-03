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

        # info on the current run
        self.bbl_addr = None
        self.stmt_idx = None
        self.ins_addr = None
        self.sim_procedure = None

        # information on exits *from* this state
        self.jumpkind = None
        self.guard = None
        self.target = None
        self.source = None

        # information on VEX temps of this IRSB
        self.temps = { }

        # variable analysis of this block
        self.input_variables = SimVariableSet()
        self.used_variables = SimVariableSet()

        if log is not None:
            self.events.extend(log.events)
            self.temps.update(log.temps)
            self.jumpkind = log.jumpkind
            self.guard = log.guard
            self.target = log.target
            self.source = log.source

            self.input_variables |= log.input_variables
            self.used_variables |= log.used_variables

            self.bbl_addr = log.bbl_addr
            self.stmt_idx = log.stmt_idx
            self.ins_addr = log.ins_addr
            self.sim_procedure = log.sim_procedure

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

    def merge(self, others, flag, flag_values): #pylint:disable=unused-argument
        all_events = [ e.events for e in itertools.chain([self], others) ]
        self.events = [ SimEvent(self.state, 'merge', event_lists=all_events) ]
        return False, [ ]

    def widen(self, others, flag, flag_values):

        # Just call self.merge() to perform a merging
        self.merge(others, flag, flag_values)

        return False

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
from ..s_variable import SimVariableSet
SimStateLog.register_default('log', SimStateLog)

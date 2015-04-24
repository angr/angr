#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.plugins.scratch")

from .plugin import SimStatePlugin
class SimStateScratch(SimStatePlugin):
    def __init__(self, scratch=None):
        SimStatePlugin.__init__(self)

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
        self.ignored_variables = None

        if scratch is not None:
            self.temps.update(scratch.temps)
            self.jumpkind = scratch.jumpkind
            self.guard = scratch.guard
            self.target = scratch.target
            self.source = scratch.source

            self.input_variables |= scratch.input_variables
            self.used_variables |= scratch.used_variables
            self.ignored_variables = None if scratch.ignored_variables is None else scratch.ignored_variables.copy()

            self.bbl_addr = scratch.bbl_addr
            self.stmt_idx = scratch.stmt_idx
            self.ins_addr = scratch.ins_addr
            self.sim_procedure = scratch.sim_procedure

    def copy(self):
        return SimStateScratch(scratch=self)

    def merge(self, others, flag, flag_values): #pylint:disable=unused-argument
        return False, [ ]

    def widen(self, others, flag, flag_values):

        # Just call self.merge() to perform a merging
        self.merge(others, flag, flag_values)

        return False

    def clear(self):
        s = self.state
        self.__init__()
        self.state = s

    def update_ignored_variables(self):
        self.ignored_variables = self.used_variables.complement(self.input_variables)

from ..s_variable import SimVariableSet
SimStateScratch.register_default('scratch', SimStateScratch)

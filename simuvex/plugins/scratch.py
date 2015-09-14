#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.plugins.scratch")

import claripy

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
        self.guard = claripy.true
        self.target = None
        self.source = None
        self.exit_stmt_idx = None

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
            self.exit_stmt_idx = scratch.exit_stmt_idx

            self.input_variables |= scratch.input_variables
            self.used_variables |= scratch.used_variables
            self.ignored_variables = None if scratch.ignored_variables is None else scratch.ignored_variables.copy()

            self.bbl_addr = scratch.bbl_addr
            self.stmt_idx = scratch.stmt_idx
            self.ins_addr = scratch.ins_addr
            self.sim_procedure = scratch.sim_procedure

    def tmp_expr(self, tmp):
        '''
        Returns the Claripy expression of a VEX temp value.

        @param tmp: the number of the tmp
        @param simplify: simplify the tmp before returning it
        @returns a Claripy expression of the tmp
        '''
        self.state._inspect('tmp_read', BP_BEFORE, tmp_read_num=tmp)
        v = self.temps[tmp]
        self.state._inspect('tmp_read', BP_AFTER, tmp_read_expr=v)
        return v

    def store_tmp(self, tmp, content):
        '''
        Stores a Claripy expression in a VEX temp value.

        @param tmp: the number of the tmp
        @param content: a Claripy expression of the content
        '''
        self.state._inspect('tmp_write', BP_BEFORE, tmp_write_num=tmp, tmp_write_expr=content)

        if o.SYMBOLIC_TEMPS not in self.state.options:
            # Non-symbolic
            self.temps[tmp] = content
        else:
            # Symbolic
            self.state.add_constraints(self.temps[tmp] == content)

        self.state._inspect('tmp_write', BP_AFTER)


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
from .. import s_options as o
from .inspect import BP_AFTER, BP_BEFORE
SimStateScratch.register_default('scratch', SimStateScratch)

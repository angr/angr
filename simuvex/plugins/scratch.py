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
        self.bbl_addr_list = None
        self.stack_pointer_list = None

        # information on exits *from* this state
        self.jumpkind = None
        self.guard = claripy.true
        self.target = None
        self.source = None
        self.exit_stmt_idx = None
        self.executed_block_count = 0 # the number of blocks that was executed here
        self.executed_syscall_count = 0 # the number of system calls that was executed here
        self.executed_instruction_count = -1 # the number of instructions that was executed
        self.avoidable = True

        # information on VEX temps of this IRSB
        self.temps = { }

        # variable analysis of this block
        self.input_variables = SimVariableSet()
        self.used_variables = SimVariableSet()
        self.ignored_variables = None

        # dirtied addresses, for dealing with self-modifying code
        self.dirty_addrs = set()
        self.num_insns = 0

        if scratch is not None:
            self.temps.update(scratch.temps)
            self.jumpkind = scratch.jumpkind
            self.guard = scratch.guard
            self.target = scratch.target
            self.source = scratch.source
            self.exit_stmt_idx = scratch.exit_stmt_idx
            self.executed_block_count = scratch.executed_block_count
            self.executed_syscall_count = scratch.executed_syscall_count
            self.executed_instruction_count = scratch.executed_instruction_count

            if scratch.input_variables is not None:
                self.input_variables |= scratch.input_variables
            if scratch.used_variables is not None:
                self.used_variables |= scratch.used_variables
            self.ignored_variables = None if scratch.ignored_variables is None else scratch.ignored_variables.copy()

            self.bbl_addr = scratch.bbl_addr
            self.stmt_idx = scratch.stmt_idx
            self.ins_addr = scratch.ins_addr
            self.sim_procedure = scratch.sim_procedure
            self.bbl_addr_list = scratch.bbl_addr_list
            self.stack_pointer_list = scratch.stack_pointer_list

        # priveleges
        self._priv_stack = [False]

    @property
    def priv(self):
        return self._priv_stack[-1]

    def push_priv(self, priv):
        self._priv_stack.append(priv)

    def pop_priv(self):
        self._priv_stack.pop()
        if len(self._priv_stack) == 0:
            raise SimValueError("Priv stack is empty")

    def tmp_expr(self, tmp):
        """
        Returns the Claripy expression of a VEX temp value.

        :param tmp: the number of the tmp
        :param simplify: simplify the tmp before returning it
        :returns: a Claripy expression of the tmp
        """
        self.state._inspect('tmp_read', BP_BEFORE, tmp_read_num=tmp)
        v = self.temps[tmp]
        self.state._inspect('tmp_read', BP_AFTER, tmp_read_expr=v)
        return v

    def store_tmp(self, tmp, content):
        """
        Stores a Claripy expression in a VEX temp value.

        :param tmp: the number of the tmp
        :param content: a Claripy expression of the content
        """
        self.state._inspect('tmp_write', BP_BEFORE, tmp_write_num=tmp, tmp_write_expr=content)
        tmp = self.state._inspect_getattr('tmp_write_num', tmp)
        content = self.state._inspect_getattr('tmp_write_expr', content)

        if o.SYMBOLIC_TEMPS not in self.state.options:
            # Non-symbolic
            self.temps[tmp] = content
        else:
            # Symbolic
            self.state.add_constraints(self.temps[tmp] == content)

        self.state._inspect('tmp_write', BP_AFTER)


    def copy(self):
        return SimStateScratch(scratch=self)

    def merge(self, others, merge_conditions):
        return False

    def widen(self, others):
        return False

    def clear(self):
        s = self.state
        self.__init__()
        self.state = s

    def update_ignored_variables(self):
        self.ignored_variables = self.used_variables.complement(self.input_variables)

from ..s_variable import SimVariableSet
from ..s_errors import SimValueError
from .. import s_options as o
from .inspect import BP_AFTER, BP_BEFORE
SimStateScratch.register_default('scratch', SimStateScratch)

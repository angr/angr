from __future__ import annotations
import logging

import claripy

from .base import SimSootStmt

l = logging.getLogger("angr.engines.soot.statements.switch")


class SwitchBase(SimSootStmt):
    def _execute(self):
        # the key determines the selected table entry
        key = self._translate_value(self.stmt.key)
        key_val = self.state.memory.load(key)

        # init list for taking the default jmp target
        # => this is used if the key value does not match with
        #    any of the given entries
        default_jmp_conditions = []

        # add all targets, conditioned by the key value
        for lookup_value, target in self.stmt.lookup_values_and_targets.items():
            jmp_target = self._get_bb_addr_from_instr(target)
            jmp_condition = lookup_value == key_val
            self._add_jmp_target(jmp_target, jmp_condition)
            # add condition for the default target
            default_jmp_conditions += [(lookup_value != key_val)]

        # add default target
        default_jmp_target = self._get_bb_addr_from_instr(self.stmt.default_target)
        default_jmp_cond = claripy.And(*default_jmp_conditions)
        self._add_jmp_target(default_jmp_target, default_jmp_cond)


class SimSootStmt_TableSwitch(SwitchBase):
    pass


class SimSootStmt_LookupSwitch(SwitchBase):
    pass

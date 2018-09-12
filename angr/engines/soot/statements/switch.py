
import logging

from claripy import Or

from .base import SimSootStmt

l = logging.getLogger('angr.engines.soot.statements.switch')


class SimSootStmt_TableSwitch(SimSootStmt):
    def _execute(self):
        # the key determines the selected table entry
        key = self._translate_value(self.stmt.key)
        key_val = self.state.memory.load(key)

        # add all targets, conditioned by the key value
        for lookup_value, target in self.stmt.lookup_values_and_targets.items():
            jmp_target = self._get_bb_addr_from_instr(target)
            jmp_condition = (lookup_value == key_val)
            self._add_jmp_target(jmp_target, jmp_condition)

        # add default target
        # => this is used if the key value is smaller/bigger than the
        #    lowest/highest entry
        default_jmp_target = self._get_bb_addr_from_instr(self.stmt.default_target)
        default_jmp_cond = Or(key_val.SGT(self.stmt.high_index),
                              key_val.SLT(self.stmt.low_index))
        self._add_jmp_target(default_jmp_target, default_jmp_cond)


from .base import SimSootStmt
from archinfo.arch_soot import SootAddressDescriptor
import logging
from ..exceptions import IncorrectLocationException
from claripy import Or

l = logging.getLogger('angr.engines.soot.statements.switch')

class SimSootStmt_TableSwitch(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_TableSwitch, self).__init__(stmt, state)

    def _execute(self):

        self.state.scratch.jump = True
        self.state.scratch.jump_targets_with_conditions = []

        # the key determines the selected entry
        key = self._translate_value(self.stmt.key)
        key_val = self.state.memory.load(key)

        # get current method
        method = self.state._ip.method

        # add all targets, conditioned by the key value
        for lookup_value, target in self.stmt.lookup_values_and_targets.items():
            jmp_target = self._get_addr(method, instr_idx=target)
            jmp_condition = (lookup_value == key_val)
            self.state.scratch.jump_targets_with_conditions.append(
                (jmp_target, jmp_condition)
            )
        
        # add default target
        # => this is used if the key value is smaller/bigger than the lowest/highest entry
        default_jmp_target = self._get_addr(method, instr_idx=self.stmt.default_target)
        default_jmp_condition = Or(key_val.SGT(self.stmt.high_index), 
                                   key_val.SLT(self.stmt.low_index))
        self.state.scratch.jump_targets_with_conditions.append(
                (default_jmp_target, default_jmp_condition)
        )


    def _get_addr(self, method_descriptor, instr_idx):
        method = self.state.regs._ip_binary.get_method(method_descriptor)
        try:
            bb_idx = method.block_by_label[instr_idx].idx
        except KeyError:
            l.warning("Possible jump to a non-existing bb %s --> %d" % (self.state._ip, self.stmt.target))
            raise IncorrectLocationException()
        return SootAddressDescriptor(self.state._ip.method, bb_idx, 0)

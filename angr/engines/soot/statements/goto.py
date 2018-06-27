
from .base import SimSootStmt
from archinfo.arch_soot import SootAddressDescriptor

import logging
l = logging.getLogger('angr.engines.soot.statements.goto')


class SimSootStmt_Goto(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Goto, self).__init__(stmt, state)

    def _execute(self):
        # get new addr
        java_binary = self.state.regs._ip_binary
        method = java_binary.get_soot_method(self.state._ip.method)
        try:
            bb_idx = method.block_by_label[self.stmt.target].idx
        except KeyError:
            l.warning("Trying to jump to a non-existing bb %s --> %d"
                      % (self.state._ip, self.stmt.target))
            raise IncorrectLocationException()
        new_addr = SootAddressDescriptor(self.state._ip.method, bb_idx, 0)
        # add jmp target
        self._add_jmp_target(target=new_addr, 
                             condition=self.state.solver.true)

from ..exceptions import IncorrectLocationException

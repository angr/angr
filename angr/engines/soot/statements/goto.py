
from .base import SimSootStmt
from archinfo.arch_soot import SootAddressDescriptor
import logging


l = logging.getLogger('angr.engines.soot.statements.goto')

class SimSootStmt_Goto(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Goto, self).__init__(stmt, state)

    def _execute(self):
        method = next(self.state.regs._ip_binary.get_method(self.state._ip.method))
        try:
            bb_idx = method.block_by_label[self.stmt.target].idx
        except KeyError:
            l.warning("Trying to jump to a non-existing bb %s --> %d" % (self.state._ip, self.stmt.target))
            raise IncorrectLocationException()
        new_addr = SootAddressDescriptor(self.state._ip.method, bb_idx, 0)
        self.state.scratch.jump = True
        self.state.scratch.jump_targets_with_conditions = [(new_addr, self.state.se.true)]


from ..exceptions import IncorrectLocationException

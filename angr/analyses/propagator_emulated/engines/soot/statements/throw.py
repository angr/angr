
import logging

from .base import SimSootStmt
from archinfo.arch_soot import SootAddressTerminator

l = logging.getLogger(name=__name__)


class SimSootStmt_Throw(SimSootStmt):
    def _execute(self):
        # TODO: implement simprocedure to throw exception
        self._add_jmp_target(target=SootAddressTerminator(),
                             condition=self.state.solver.true)

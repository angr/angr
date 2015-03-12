from . import SimIRStmt
#from ... import s_options as o
#from ...s_action_object import SimActionObject
#from ...s_action import SimActionData
from .. import size_bytes

import logging
l = logging.getLogger('simuvex.vex.statements.llsc')

class SimIRStmt_LLSC(SimIRStmt):
    def _execute(self):
        l.warning("LLSC is handled soundly but imprecisely.")
        addr = self._translate_expr(self.stmt.addr)

        if self.stmt.storedata is None:
            # it's a load-linked
            load_size = size_bytes(self.irsb.tyenv.types[self.stmt.result])
            data = self.state.mem_expr(addr.expr, load_size, endness=self.stmt.endness)
            self.state.store_tmp(self.stmt.result, data)
        else:
            # it's a store-conditional
            result = self.state.se.Unconstrained('llcd_result', 1)

            new_data = self._translate_expr(self.stmt.storedata)
            old_data = self.state.mem_expr(addr.expr, new_data.size_bytes(), endness=self.stmt.endness)

            store_data = self.state.se.If(result == 1, new_data.expr, old_data)
            self.state.store_mem(addr.expr, store_data)
            self.state.store_tmp(self.stmt.result, result)

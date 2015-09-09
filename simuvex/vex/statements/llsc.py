from . import SimIRStmt
#from ... import s_options as o
#from ...s_action_object import SimActionObject
#from ...s_action import SimActionData
from .. import size_bytes

import logging
l = logging.getLogger('simuvex.vex.statements.llsc')

# TODO: memory read SimActions
# TODO: tmp write SimActions

class SimIRStmt_LLSC(SimIRStmt):
    def _execute(self):
        #l.warning("LLSC is handled soundly but imprecisely.")
        addr = self._translate_expr(self.stmt.addr)

        if self.stmt.storedata is None:
            # it's a load-linked
            load_size = size_bytes(self.irsb.tyenv.types[self.stmt.result])
            data = self.state.memory.load(addr.expr, load_size, endness=self.stmt.endness)
            self.state.scratch.store_tmp(self.stmt.result, data)
        else:
            # it's a store-conditional
            #result = self.state.se.Unconstrained('llcd_result', 1)

            #new_data = self._translate_expr(self.stmt.storedata)
            #old_data = self.state.memory.load(addr.expr, new_data.size_bytes(), endness=self.stmt.endness)

            #store_data = self.state.se.If(result == 1, new_data.expr, old_data)

            # for single-threaded programs, an SC will never fail. For now, we just assume it succeeded.
            store_data = self._translate_expr(self.stmt.storedata)
            result = self.state.se.BVV(1, 1)

            # the action
            if o.TRACK_MEMORY_ACTIONS in self.state.options:
                data_ao = SimActionObject(store_data.expr, reg_deps=store_data.reg_deps(), tmp_deps=store_data.tmp_deps())
                addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
                #guard_ao = SimActionObject(result == 1)
                size_ao = SimActionObject(store_data.expr.length)
                a = SimActionData(self.state, self.state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, size=size_ao)
                self.actions.append(a)
            else:
                a = None

            self.state.memory.store(addr.expr, store_data.expr, action=a)
            self.state.scratch.store_tmp(self.stmt.result, result)

from ...s_action_object import SimActionObject
from ...s_action import SimActionData
from ... import s_options as o

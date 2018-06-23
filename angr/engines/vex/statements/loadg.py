from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionData

from . import SimIRStmt, SimStatementError

class SimIRStmt_LoadG(SimIRStmt):
    def _execute(self):
        addr = self._translate_expr(self.stmt.addr)
        alt = self._translate_expr(self.stmt.alt)
        guard = self._translate_expr(self.stmt.guard)

        read_type, converted_type = self.stmt.cvt_types
        read_size = self.size_bytes(read_type)
        converted_size = self.size_bytes(converted_type)

        read_expr = self.state.memory.load(addr.expr, read_size, endness=self.stmt.end, condition=guard.expr != 0)
        if read_size == converted_size:
            converted_expr = read_expr
        elif "S" in self.stmt.cvt:
            converted_expr = read_expr.sign_extend(converted_size*self.state.arch.byte_width -
                                                   read_size*self.state.arch.byte_width)
        elif "U" in self.stmt.cvt:
            converted_expr = read_expr.zero_extend(converted_size*self.state.arch.byte_width -
                                                   read_size*self.state.arch.byte_width)
        else:
            raise SimStatementError("Unrecognized IRLoadGOp %s!" % self.stmt.cvt)

        read_expr = self.state.se.If(guard.expr != 0, converted_expr, alt.expr)

        if o.ACTION_DEPS in self.state.options:
            reg_deps = addr.reg_deps() | alt.reg_deps() | guard.reg_deps()
            tmp_deps = addr.tmp_deps() | alt.tmp_deps() | guard.tmp_deps()
        else:
            reg_deps = None
            tmp_deps = None
        self.state.scratch.store_tmp(self.stmt.dst, read_expr, reg_deps, tmp_deps)

        if o.TRACK_MEMORY_ACTIONS in self.state.options:
            data_ao = SimActionObject(converted_expr)
            alt_ao = SimActionObject(alt.expr, reg_deps=alt.reg_deps(), tmp_deps=alt.tmp_deps())
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            guard_ao = SimActionObject(guard.expr, reg_deps=guard.reg_deps(), tmp_deps=guard.tmp_deps())
            size_ao = SimActionObject(self.size_bits(converted_type))

            r = SimActionData(self.state, self.state.memory.id, SimActionData.READ, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao, fallback=alt_ao)
            self.actions.append(r)

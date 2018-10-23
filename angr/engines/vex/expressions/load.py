from .base import SimIRExpr, _nonset
from .... import sim_options as o
from ....state_plugins.sim_action import SimActionData
from ....state_plugins.sim_action_object import SimActionObject
from ....errors import SimUninitializedAccessError

class SimIRExpr_Load(SimIRExpr):
    def _execute(self):
        # size of the load
        size = self.size_bytes(self._expr.type)
        self.type = self._expr.type

        # get the address expression and track stuff
        addr = self._translate_expr(self._expr.addr)

        if o.UNINITIALIZED_ACCESS_AWARENESS in self.state.options:
            if getattr(addr.expr._model_vsa, 'uninitialized', False):
                raise SimUninitializedAccessError('addr', addr.expr)

        # if we got a symbolic address and we're not in symbolic mode, just return a symbolic value to deal with later
        if o.DO_LOADS not in self.state.options:
            self.expr = self.state.solver.Unconstrained("load_expr_0x%x_%d" % (
                self.state.scratch.ins_addr, self.state.scratch.stmt_idx
            ), size*self.state.arch.byte_width)
        else:

            # load from memory and fix endianness
            self.expr = self.state.memory.load(addr.expr, size, endness=self._expr.endness)

        if self.type.startswith('Ity_F'):
            self.expr = self.expr.raw_to_fp()

        # finish it and save the mem read
        self._post_process()
        if o.TRACK_MEMORY_ACTIONS in self.state.options:
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            r = SimActionData(self.state, self.state.memory.id, SimActionData.READ, addr=addr_ao, size=self.size_bits(self._expr.type), data=self.expr)
            self.actions.append(r)

    def reg_deps(self):

        # only return data dependencies
        if len(self.actions) == 0 or o.ACTION_DEPS not in self.state.options:
            return _nonset
        else:
            return frozenset.union(
                *[r.data.reg_deps for r in self.actions if type(r) == SimActionData and r.type == 'mem'])

    def tmp_deps(self):

        # only return data dependences
        if len(self.actions) == 0 or o.ACTION_DEPS not in self.state.options:
            return _nonset
        else:
            return frozenset.union(
                *[r.data.tmp_deps for r in self.actions if type(r) == SimActionData and r.type == 'mem'])

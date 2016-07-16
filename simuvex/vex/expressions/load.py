from .base import SimIRExpr, _nonset
from .. import size_bytes, size_bits
from ... import s_options as o
from ...s_action import SimActionData
from ...s_action_object import SimActionObject
from ...s_errors import SimUninitializedAccessError

class SimIRExpr_Load(SimIRExpr):
    def _execute(self):
        # size of the load
        size = size_bytes(self._expr.type)
        self.type = self._expr.type

        # get the address expression and track stuff
        addr = self._translate_expr(self._expr.addr)

        if o.FRESHNESS_ANALYSIS in self.state.options:
            self.state.scratch.input_variables.add_memory_variables(self.state.memory.normalize_address(addr.expr), size)

        if o.UNINITIALIZED_ACCESS_AWARENESS in self.state.options:
            if getattr(addr.expr._model_vsa, 'uninitialized', False):
                raise SimUninitializedAccessError('addr', addr.expr)

        # if we got a symbolic address and we're not in symbolic mode, just return a symbolic value to deal with later
        if o.DO_LOADS not in self.state.options:
            self.expr = self.state.se.Unconstrained("load_expr_0x%x_%d" % (self.imark.addr, self.stmt_idx), size*8)
        else:

            # load from memory and fix endianness
            self.expr = self.state.memory.load(addr.expr, size, endness=self._expr.endness)

        if self.type.startswith('Ity_F'):
            self.expr = self.expr.raw_to_fp()

        # finish it and save the mem read
        self._post_process()
        if o.TRACK_MEMORY_ACTIONS in self.state.options:
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            r = SimActionData(self.state, self.state.memory.id, SimActionData.READ, addr=addr_ao, size=size_bits(self._expr.type), data=self.expr)
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

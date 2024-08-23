from __future__ import annotations
import itertools

from ...sim_procedure import SimProcedure
from ...engines.soot.values import SimSootValue_Local, SimSootValue_ParamRef, translate_value
from ...engines.soot.expressions import translate_expr


class JavaSimProcedure(SimProcedure):
    @property
    def is_java(self):
        return True

    @property
    def _engine(self):
        return self.project.factory.default_engine  # FIXME: Currently we assume that it must be a SootMixin

    def _setup_args(self, inst, state, _):
        sim_args = []
        # try to get 'this' reference
        try:
            this_ref = state.javavm_memory.load(addr=SimSootValue_Local("this", None))
            sim_args += [this_ref]
        except KeyError:
            pass
        # fetch all function arguments from memory
        for idx in itertools.count():
            try:
                param = state.javavm_memory.load(addr=SimSootValue_ParamRef(idx, None))
            except KeyError:
                break
            sim_args += [param]
        return sim_args

    def _compute_ret_addr(self, expr):
        return self.state.callstack.ret_addr

    def _prepare_ret_state(self):
        self._engine.prepare_return_state(self.state, self.ret_expr)

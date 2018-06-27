
import angr

import itertools
from angr.engines.soot.values import translate_value
from angr.engines.soot.expressions import translate_expr

from ...engines.soot.values import SimSootValue_Local, SimSootValue_ParamRef


class JavaSimProcedure(angr.SimProcedure):

    def __init__(self, **kwargs):
        super(JavaSimProcedure, self).__init__(**kwargs)

    @property
    def _engine(self):
        return self.project.factory.default_engine  # FIXME: Currently we assume that it must be a SimEngineSoot

    def _setup_args(self, inst, state, _):
        sim_args = []
        # try to get 'this' reference
        try:
            this_ref = state.javavm_memory.load(addr=SimSootValue_Local('this', None))
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

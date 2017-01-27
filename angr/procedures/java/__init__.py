
import angr

from angr.engines.soot.values import translate_value
from angr.engines.soot.expressions import translate_expr


class JavaSimProcedure(angr.SimProcedure):

    def __init__(self, **kwargs):
        super(JavaSimProcedure, self).__init__(**kwargs)

    @property
    def _engine(self):
        return self.project.factory.default_engine  # FIXME: Currently we assume that it must be a SimEngineSoot

    def _setup_args(self, inst, state, arguments):
        ie = state.scratch.invoke_expr
        all_args = list()
        all_args.append(ie.base)
        all_args += ie.args
        sim_args = [ ]
        for arg in all_args:
            arg_cls_name = arg.__class__.__name__
            # TODO is this correct?
            if "Constant" not in arg_cls_name:
                v = state.memory.load(translate_value(arg), frame=1)
            else:
                v = translate_expr(arg, state).expr
            sim_args.append(v)

        return sim_args

    def _compute_ret_addr(self, expr):
        return self.state.callstack.ret_addr

    def _prepare_ret_state(self):
        self._engine.prepare_return_state(self.state, self.ret_expr)

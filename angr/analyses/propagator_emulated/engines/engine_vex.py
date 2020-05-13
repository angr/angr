import claripy
import pyvex

from ...code_location import CodeLocation
from ...cfg.cfg_emulated import StackTouchedAnnotation
from ....engines.vex.heavy.heavy import HeavyVEXMixin



class PropagatorEmulatedHeavyVEXMixin(HeavyVEXMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr):
        result = super()._handle_vex_expr(expr)
        ### Only save the constant if it is not touched by the stack
        if not(issubclass(type(result[0]), claripy.ast.base.Base) and len(result[0].annotations) != 0 and isinstance(result[0].annotations[0], StackTouchedAnnotation)):
            if not self.state.solver.symbolic(result[0]) and not(type(expr) == pyvex.expr.Const):
                const_class = pyvex.const.ty_to_const_class(expr.result_type(self.state.scratch.tyenv))
                code_loc = CodeLocation(self.irsb.addr, self.stmt_idx, block_id=self.state.globals['block_id'])
                self.state.globals['abstract_state'].add_replacement(code_loc, expr, pyvex.expr.Const(const_class(self.state.solver.eval(result[0]))))
        return self._instrument_vex_expr(result)

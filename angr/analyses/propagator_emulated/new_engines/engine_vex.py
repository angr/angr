from ....engines.vex.heavy.heavy import HeavyVEXMixin
import pyvex
from ...code_location import CodeLocation

class PropagatorEmulatedHeavyVEXMixin(HeavyVEXMixin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr):
        result = super()._handle_vex_expr(expr)
        if not self.state.solver.symbolic(result[0]) and not(type(expr) == pyvex.expr.Const):
            const_class = pyvex.const.ty_to_const_class(expr.result_type(self.state.scratch.tyenv))
            code_loc = CodeLocation(self.irsb.addr, self.stmt_idx, block_id=self.state.globals['block_id'])
            self.state.globals['abstract_state'].add_replacement(code_loc, expr, pyvex.expr.Const(const_class(self.state.solver.eval(result[0]))))
        return result
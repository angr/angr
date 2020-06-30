import claripy
import pyvex

from ....code_location import CodeLocation
from ...cfg.cfg_emulated import StackTouchedAnnotation
from ....engines.vex.heavy.heavy import HeavyVEXMixin



class PropagatorEmulatedHeavyVEXMixin(HeavyVEXMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr):
        result = super()._handle_vex_expr(expr)
        ### Only save the constant if it is not touched by the stack
        code_loc = CodeLocation(self.irsb.addr, self.stmt_idx, block_id=self.state.globals['block_id'])
        if not(issubclass(type(result[0]), claripy.ast.base.Base) and len(result[0].annotations) != 0 and isinstance(result[0].annotations[0], StackTouchedAnnotation)):
            ### Check if the result is not symbolic and not already a constant(in which case there is no need to replace)
            if not self.state.solver.symbolic(result[0]) and not(type(expr) == pyvex.expr.Const):
                const_class = pyvex.const.ty_to_const_class(expr.result_type(self.state.scratch.tyenv))
                self.state.globals['abstract_state'].add_replacement(code_loc, expr, pyvex.expr.Const(const_class(self.state.solver.eval(result[0]))))
            ### Check if the result is symbolic now, but was constant in some previous iteration and put in the replacements. If so then remove the replacement
            elif self.state.solver.symbolic(result[0]) and expr in self.state.globals['abstract_state']._replacements[code_loc]:
                del self.state.globals['abstract_state']._replacements[code_loc][expr]
        return self._instrument_vex_expr(result)

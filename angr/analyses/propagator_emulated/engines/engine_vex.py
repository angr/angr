import claripy
import pyvex

from ....code_location import CodeLocation
from ...cfg.cfg_vm_deobfuscation import StackTouchedAnnotation, DataRegionAnnotation
from ....engines.vex.heavy.heavy import HeavyVEXMixin
from ...vm_deobfuscation.vm_deobfuscation import DataSensitiveRdTmp, DataSensitiveU32, DataSensitiveU64



class PropagatorEmulatedHeavyVEXMixin(HeavyVEXMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr):
        result = super()._handle_vex_expr(expr)
        ### Only save the constant if it is not touched by the stack
        code_loc = CodeLocation(self.irsb.addr, self.stmt_idx, block_id=self.state.globals['block_id'])
        stack_touched = False
        for annotation in result[0].annotations:
            if isinstance(annotation, StackTouchedAnnotation):
                stack_touched = True
                break

        if not stack_touched:
            ### Check if the result is not symbolic and not already a constant(in which case there is no need to replace)
            if not self.state.solver.symbolic(result[0]) and not(isinstance(expr, pyvex.expr.Const)):
                const_class = pyvex.const.ty_to_const_class(expr.result_type(self.state.scratch.tyenv))
                if isinstance(expr, DataSensitiveRdTmp):
                    if const_class == pyvex.const.U64:
                        const_class = DataSensitiveU64
                    elif const_class == pyvex.const.U32:
                        const_class = DataSensitiveU32
                    self.state.globals['abstract_state'].add_replacement(code_loc, expr, pyvex.expr.Const(
                        const_class(self.state.solver.eval(result[0]), expr.block_id)))
                else:
                    self.state.globals['abstract_state'].add_replacement(code_loc, expr, pyvex.expr.Const(const_class(self.state.solver.eval(result[0]))))
            ### Check if the result is symbolic now, but was constant in some previous iteration and put in the replacements. If so then remove the replacement
            elif self.state.solver.symbolic(result[0]) and expr in self.state.globals['abstract_state']._replacements[code_loc]:
                del self.state.globals['abstract_state']._replacements[code_loc][expr]
        return self._instrument_vex_expr(result)

    def _handle_vex_defaultexit(self, expr, jumpkind):
        if isinstance(expr, pyvex.expr.RdTmp):
            self.state.globals['cur_block_id'] = expr.block_id
        else:
            self.state.globals['cur_block_id'] = expr.con.block_id
        super()._handle_vex_defaultexit(expr, jumpkind)

    def _handle_vex_stmt_Exit(self, stmt):
        self.state.globals['cur_block_id'] = stmt.dst.block_id
        super()._handle_vex_stmt_Exit(stmt)


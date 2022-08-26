import claripy
import pyvex

from ....code_location import CodeLocation
from ...cfg.cfg_vm_deobfuscation import StackTouchedAnnotation, DataRegionAnnotation
from ....engines.vex.heavy.heavy import HeavyVEXMixin
from ...vm_deobfuscation.vm_deobfuscation import DataSensitiveRdTmp, DataSensitiveU32, DataSensitiveU64
from ...cfg.cfg_job_base import BlockID



class PropagatorEmulatedHeavyVEXMixin(HeavyVEXMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr):
        result = super()._handle_vex_expr(expr)
        simp_result = result[0]
        if self.state.solver.symbolic(result[0]):
            simp_result = self.state.solver.simplify(result[0])
        # ### Only save the constant if it is not touched by the stack
        code_loc = CodeLocation(self.irsb.addr, self.stmt_idx, block_id=self.state.globals['cur_block_id'])
        stack_touched = False
        for annotation in result[0].annotations:
            if isinstance(annotation, StackTouchedAnnotation):
                import ipdb;ipdb.set_trace()
                stack_touched = True
                break

        if not stack_touched:
            ### Check if the result is not symbolic and not already a constant(in which case there is no need to replace)
            ## also make sure there's only one possible solution....... if more than one possible solns then leave it as is
            #
            # if self.state.globals['cur_block_id'] and self.state.globals['cur_block_id'].addr == 0x1400AB56C and self.state.scratch.stmt_idx == 11:
            #     import ipdb;ipdb.set_trace()
            # if self.state.solver.symbolic(result[0]) and not self.state.solver.symbolic(self.state.solver.simplify(result[0])) and "precon_sp_24_64" not in result[0].variables:
            #     print(self.state.solver.simplify(result[0]))
            #     import ipdb;ipdb.set_trace()
            # if self.state.solver.symbolic(result[0]) and not self.state.solver.eval_one(self.state.solver.simplify(result[0])) and "precon_sp_24_64" not in result[0].variables:
            #     print(self.state.solver.eval_one(self.state.solver.simplify(result[0])))
            #     import ipdb;ipdb.set_trace()

            # Check if the result is a constant but the value is different now, from the previously saved constant value
            # if not self.state.solver.symbolic(simp_result) and expr in self.state.globals['abstract_state']._replacements[code_loc] and self.state.globals['abstract_state']._replacements[code_loc][expr].con.value != simp_result.args[0]:
            #     print(self.state.globals['abstract_state']._replacements[code_loc][expr])
            #     print(simp_result)
            #     import ipdb;ipdb.set_trace()

            if not self.state.solver.symbolic(simp_result) and not(isinstance(expr, pyvex.expr.Const)):
                const_class = pyvex.const.ty_to_const_class(expr.result_type(self.state.scratch.tyenv))
                if len(simp_result.args) > 2:
                    print("Hmmm possible need to simplify the expr")
                    import ipdb;ipdb.set_trace()
                if isinstance(expr, DataSensitiveRdTmp):
                    if const_class == pyvex.const.U64:
                        const_class = DataSensitiveU64
                    elif const_class == pyvex.const.U32:
                        const_class = DataSensitiveU32
                    self.state.globals['abstract_state'].add_replacement(code_loc, expr, pyvex.expr.Const(
                        const_class(simp_result.args[0], expr.block_id)))
                else:
                    self.state.globals['abstract_state'].add_replacement(code_loc, expr, pyvex.expr.Const(const_class(simp_result.args[0])))
            ### Check if the result is symbolic now, but was constant in some previous iteration and put in the replacements. If so then remove the replacement
            elif self.state.solver.symbolic(simp_result) and expr in self.state.globals['abstract_state']._replacements[code_loc]:
                #import ipdb;ipdb.set_trace()
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

    # def process_successors(self,
    #     successors,
    #     irsb=None,
    #     insn_text=None,
    #     insn_bytes=None,
    #     thumb=False,
    #     size=None,
    #     num_inst=None,
    #     extra_stop_points=None,
    #     opt_level=None,
    #     **kwargs):
    #
    #     super().process_successors(
    #     successors,
    #     irsb,
    #     insn_text,
    #     insn_bytes,
    #     thumb,
    #     size,
    #     num_inst,
    #     extra_stop_points,
    #     opt_level,
    #     **kwargs)
    #
    #     for succ in successors.all_successors:
    #         if succ.addr != succ.globals['cur_block_id'].addr:
    #             cur_block_id = succ.globals['cur_block_id']
    #             succ.globals['cur_block_id'] = BlockID.new(succ.addr, cur_block_id.callsite_tuples, cur_block_id.jump_type, cur_block_id.vm_vpc)
    #

from ailment import BinaryOp
from ailment.expression import VirtualVariable, Const
from ailment.statement import ConditionalJump, Assignment

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.mixins.cfg_transformation_mixin import CFGTransformationMixin


class UnreachableBranchFixer(OptimizationPass, CFGTransformationMixin):
    """
    Fix fake branches like the following case:

    ## Block 42f1ce
    00 | 0x42f1ce | LABEL_42f1ce:
    01 | 0x42f1d5 | vvar_148{stack -56} = 0x456020<64>
    02 | 0x42f1d9 | vvar_149{stack -64} = 0x8000000000000001<64>
    03 | 0x42f1dd | vvar_88{reg 16} = vvar_149{stack -64}
    04 | 0x42f1e8 | if ((vvar_88{reg 16} == 0x8000000000000001<64>)) { Goto 0x42f206<64> } else { Goto 0x42f229<64> }

    I have no idea why this happens.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Fix fake branches"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _calculate_vvar_val(self, vvar, block):
        val = vvar
        for stmt in reversed(block.statements):
            if isinstance(val, VirtualVariable) and isinstance(stmt, Assignment) and stmt.dst.likes(val):
                val = stmt.src
            if not isinstance(val, VirtualVariable):
                break
        return val

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            if block.statements and isinstance(block.statements[-1], ConditionalJump):
                jump: ConditionalJump = block.statements[-1]
                cond = jump.condition
                if (
                    isinstance(cond, BinaryOp)
                    and cond.op == "CmpEQ"
                    and isinstance(cond.operands[0], VirtualVariable)
                    and isinstance(cond.operands[1], Const)
                ):
                    vvar = cond.operands[0]
                    val = cond.operands[1]
                    vvar_val = self._calculate_vvar_val(vvar, block)
                    if vvar_val.likes(val):
                        self.remove_false_branch(block)

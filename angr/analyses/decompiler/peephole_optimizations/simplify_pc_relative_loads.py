from __future__ import annotations
from ailment.expression import BinaryOp, Const, Load

from ....utils.loader import is_pc, is_in_readonly_section, is_in_readonly_segment
from .base import PeepholeOptimizationExprBase


class SimplifyPcRelativeLoads(PeepholeOptimizationExprBase):
    """
    Simplifying pc-relative loads.
    """

    __slots__ = ()

    NAME = "Simplify PC-relative loads"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        # Load(addr) + pc ==> Const()
        if expr.op == "Add" and len(expr.operands) == 2 and isinstance(expr.operands[0], Load):
            op0, op1 = expr.operands

            # check if op1 is PC
            if isinstance(op1, Const) and hasattr(expr, "ins_addr") and is_pc(self.project, expr.ins_addr, op1.value):
                # check if op0.addr points to a read-only section
                addr = op0.addr.value
                if is_in_readonly_section(self.project, addr) or is_in_readonly_segment(self.project, addr):
                    # found it!
                    # do the load first
                    try:
                        offset = self.project.loader.memory.unpack_word(addr, size=self.project.arch.bytes)
                    except KeyError:
                        return expr
                    value = offset + op1.value
                    return Const(None, None, value, self.project.arch.bits, **expr.tags)

        return expr

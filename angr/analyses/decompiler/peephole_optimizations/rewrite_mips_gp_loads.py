# pylint:disable=too-many-boolean-expressions
from ailment.expression import Load, BinaryOp, Register, Const

from .base import PeepholeOptimizationExprBase


class RewriteMipsGpLoads(PeepholeOptimizationExprBase):
    """
    Rewrite $gp-based loads to their actual values on MIPS.
    """

    __slots__ = ()

    NAME = "MIPS GP-based Loads Rewriter"
    expr_classes = (Load,)

    def optimize(self, expr: Load, **kwargs):
        # Load(addr=(gp<8> - 0x7fc0<64>), size=8, endness=Iend_LE) - replace it with gp for this function
        if self.project.arch.name not in {"MIPS32", "MIPS64"}:
            return None
        if "gp" not in self.project.kb.functions[self.func_addr].info:
            return None

        gp_offset = self.project.arch.registers["gp"][0]
        if (
            expr.size == self.project.arch.bytes
            and isinstance(expr.addr, BinaryOp)
            and expr.addr.op in {"Add", "Sub"}
            and len(expr.addr.operands) == 2
            and isinstance(expr.addr.operands[0], Register)
            and expr.addr.operands[0].reg_offset == gp_offset
            and isinstance(expr.addr.operands[1], Const)
        ):
            # just do the load...
            gp_value = self.project.kb.functions[self.func_addr].info["gp"]
            if expr.addr.op == "Add":
                addr = gp_value + expr.addr.operands[1].value
            else:  # Sub
                addr = gp_value - expr.addr.operands[1].value
            if self.project.arch.bits == 32:
                addr &= 0xFFFF_FFFF
            else:
                addr &= 0xFFFF_FFFF_FFFF_FFFF
            value = self.project.loader.memory.unpack_word(addr, size=expr.size)
            return Const(None, None, value, expr.size * self.project.arch.byte_width, **expr.tags)

        return None

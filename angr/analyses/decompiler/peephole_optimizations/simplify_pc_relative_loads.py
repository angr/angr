import archinfo
from ailment.expression import BinaryOp, Const, Load

from .base import PeepholeOptimizationExprBase


class SimplifyPcRelativeLoads(PeepholeOptimizationExprBase):
    __slots__ = ()

    name = "Simplify PC-relative loads"
    expr_classes = (BinaryOp, )

    def optimize(self, expr: BinaryOp):

        # Load(addr) + pc ==> Const()
        if expr.op == "Add" and len(expr.operands) == 2 and isinstance(expr.operands[0], Load):
            op0, op1 = expr.operands

            if isinstance(op1, Const):
                # check if op1 is PC
                if self._is_pc(expr.ins_addr, op1.value):
                    # check if op0.addr points to a read-only section
                    addr = op0.addr.value
                    if self._is_in_readonly_section(addr) or self._is_in_readonly_segment(addr):
                        # found it!
                        # do the load first
                        try:
                            offset = self.project.loader.memory.unpack_word(addr, size=self.project.arch.bytes)
                        except KeyError:
                            return expr
                        value = offset + op1.value
                        return Const(None, None, value, self.project.arch.bits, **expr.tags)

        return expr

    def _is_pc(self, pc, addr) -> bool:
        if archinfo.arch_arm.is_arm_arch(self.project.arch):
            if pc & 1 == 1:
                # thumb mode
                pc = pc - 1
                return addr == pc + 4
            else:
                # arm mode
                return addr == pc + 8
        return pc == addr

    def _is_in_readonly_section(self, addr: int) -> bool:
        sec = self.project.loader.find_section_containing(addr)
        if sec is not None:
            return not sec.is_writable
        return False

    def _is_in_readonly_segment(self, addr: int) -> bool:
        seg = self.project.loader.find_segment_containing(addr)
        if seg is not None:
            return not seg.is_writable
        return False

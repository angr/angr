from typing import Optional

import archinfo
from ailment.expression import BinaryOp, UnaryOp
from angr.project import Project
from angr.knowledge_base import KnowledgeBase


class PeepholeOptimizationStmtBase:

    __slots__ = ('project', 'kb', 'func_addr', )
    project: Project
    kb: KnowledgeBase
    func_addr: Optional[int]

    NAME = "Peephole Optimization - Statement"
    DESCRIPTION = "Peephole Optimization - Statement"
    stmt_classes = None

    def __init__(self, project: Project, kb: KnowledgeBase, func_addr: Optional[int] = None):
        self.project = project
        self.kb = kb
        self.func_addr = func_addr

    def optimize(self, stmt):
        raise NotImplementedError("_optimize() is not implemented.")


class PeepholeOptimizationExprBase:

    __slots__ = ('project', 'kb', 'func_addr', )
    project: Project
    kb: KnowledgeBase
    func_addr: Optional[int]

    NAME = "Peephole Optimization - Expression"
    DESCRIPTION = "Peephole Optimization - Expression"
    expr_classes = None

    def __init__(self, project: Project, kb: KnowledgeBase, func_addr: Optional[int] = None):
        self.project = project
        self.kb = kb
        self.func_addr = func_addr

    def optimize(self, expr):
        raise NotImplementedError("_optimize() is not implemented.")

    #
    # Util methods
    #

    @staticmethod
    def is_bool_expr(ail_expr):

        if isinstance(ail_expr, BinaryOp):
            if ail_expr.op in {'CmpEQ', 'CmpNE', 'CmpLT', 'CmpLE', 'CmpGT', 'CmpGE', 'CmpLTs', 'CmpLEs', 'CmpGTs',
                               'CmpGEs'}:
                return True
        if isinstance(ail_expr, UnaryOp) and ail_expr.op == 'Not':
            return True
        return False

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

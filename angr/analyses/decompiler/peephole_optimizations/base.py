from typing import Optional

from ailment.expression import BinaryOp, UnaryOp
from angr.project import Project
from angr.knowledge_base import KnowledgeBase


class PeepholeOptimizationStmtBase:
    """
    The base class for all peephole optimizations that are applied on AIL statements.
    """

    __slots__ = (
        "project",
        "kb",
        "func_addr",
    )
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
    """
    The base class for all peephole optimizations that are applied on AIL expressions.
    """

    __slots__ = (
        "project",
        "kb",
        "func_addr",
    )
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
            if ail_expr.op in {
                "CmpEQ",
                "CmpNE",
                "CmpLT",
                "CmpLE",
                "CmpGT",
                "CmpGE",
                "CmpLTs",
                "CmpLEs",
                "CmpGTs",
                "CmpGEs",
            }:
                return True
        if isinstance(ail_expr, UnaryOp) and ail_expr.op == "Not":
            return True
        return False

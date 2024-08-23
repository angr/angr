from __future__ import annotations
from ailment.expression import BinaryOp, UnaryOp, Expression
from ailment.statement import Statement, Assignment
from ailment import Block
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
    project: Project | None
    kb: KnowledgeBase | None
    func_addr: int | None

    NAME = "Peephole Optimization - Statement"
    DESCRIPTION = "Peephole Optimization - Statement"
    stmt_classes = None

    def __init__(self, project: Project | None, kb: KnowledgeBase | None, func_addr: int | None = None):
        self.project = project
        self.kb = kb
        self.func_addr = func_addr

    def optimize(self, stmt, stmt_idx: int | None = None, block=None, **kwargs):
        raise NotImplementedError("_optimize() is not implemented.")


class PeepholeOptimizationMultiStmtBase:
    """
    The base class for all peephole optimizations that are applied on multiple AIL statements at once.
    """

    __slots__ = (
        "project",
        "kb",
        "func_addr",
    )
    project: Project | None
    kb: KnowledgeBase | None
    func_addr: int | None

    NAME = "Peephole Optimization - Multi-statement"
    DESCRIPTION = "Peephole Optimization - Multi-statement"
    stmt_classes = None

    def __init__(self, project: Project | None, kb: KnowledgeBase | None, func_addr: int | None = None):
        self.project = project
        self.kb = kb
        self.func_addr = func_addr

    def optimize(self, stmts: list[Statement], stmt_idx: int | None = None, block=None, **kwargs):
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
    project: Project | None
    kb: KnowledgeBase | None
    func_addr: int | None

    NAME = "Peephole Optimization - Expression"
    DESCRIPTION = "Peephole Optimization - Expression"
    expr_classes = None

    def __init__(self, project: Project | None, kb: KnowledgeBase | None, func_addr: int | None = None):
        self.project = project
        self.kb = kb
        self.func_addr = func_addr

    def optimize(self, expr, **kwargs):
        raise NotImplementedError("_optimize() is not implemented.")

    #
    # Util methods
    #

    @staticmethod
    def find_definition(ail_expr: Expression, stmt_idx: int, block: Block) -> None:
        idx = stmt_idx - 1
        if idx >= 0:
            stmt = block.statements[idx]
            if isinstance(stmt, Assignment) and stmt.dst.likes(ail_expr):
                return stmt.src
        return None

    @staticmethod
    def is_bool_expr(ail_expr):
        if isinstance(ail_expr, BinaryOp) and ail_expr.op in {
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
        return bool(isinstance(ail_expr, UnaryOp) and ail_expr.op == "Not")

from typing import Optional

from ailment import Block, Assignment, Const
from ailment.expression import Convert
from ailment.statement import Statement, Label, Call, Return, ConditionalJump, Jump

from angr.rust.utils.library import normalize


class CFAMixin:
    """
    Control Flow Analysis Mixin
    """

    def __init__(self, graph, project=None):
        self._graph = graph
        self._project = project

    def num_predecessors(self, block):
        return len(list(self._graph.predecessors(block)))

    def get_one_predecessor(self, block) -> Block:
        return next(self._graph.predecessors(block))

    def num_successors(self, block):
        return len(list(self._graph.successors(block)))

    def get_one_successor(self, block) -> Block:
        return next(self._graph.successors(block))

    def first_non_label_stmt(self, block) -> Optional[Statement]:
        for stmt in block.statements:
            if not isinstance(stmt, Label):
                return stmt
        return None

    def last_stmt(self, block) -> Optional[Statement]:
        if block.statements:
            return block.statements[-1]
        return None

    def replace_stmt(self, block, stmts, replacement):
        idx = max(block.statements.index(stmt) for stmt in stmts)
        block.statements.insert(idx, replacement)
        for stmt in stmts:
            block.statements.remove(stmt)

    def terminal_call(self, block) -> Optional[Call]:
        stmt = self.last_stmt(block)
        if isinstance(stmt, (ConditionalJump, Jump)) and len(block.statements) >= 2:
            stmt = block.statements[-2]
        if isinstance(stmt, Return) and stmt.ret_exprs:
            stmt = stmt.ret_exprs[0]
            if isinstance(stmt, Convert):
                stmt = stmt.operand
        elif isinstance(stmt, Assignment):
            stmt = stmt.src
        return stmt if isinstance(stmt, Call) else None

    def match_call(self, block_or_stmt, expected, monopolize=True, use_trait_name=True):
        stmt = self.terminal_call(block_or_stmt) if isinstance(block_or_stmt, Block) else block_or_stmt
        if isinstance(stmt, Call):
            name = None
            if isinstance(stmt.target, str):
                name = normalize(stmt.target, monopolize=monopolize, use_trait_name=use_trait_name)
            elif isinstance(stmt.target, Const) and stmt.target.value in self._project.kb.functions:
                func = self._project.kb.functions[stmt.target.value]
                name = normalize(func.name, monopolize=monopolize, use_trait_name=use_trait_name)
            if name in expected:
                return name
        return None

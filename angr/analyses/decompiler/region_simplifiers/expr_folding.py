# pylint:disable=missing-class-docstring,unused-argument
from collections import defaultdict
from typing import Optional, Any, Dict, TYPE_CHECKING

import ailment
from ailment import Expression, Block
from ailment.statement import Statement

from ..ailblock_walker import AILBlockWalker
from ..sequence_walker import SequenceWalker
from ..structurer_nodes import ConditionNode, ConditionalBreakNode, LoopNode

if TYPE_CHECKING:
    from angr.sim_variable import SimVariable
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal


class LocationBase:

    __slots__ = ()


class StatementLocation(LocationBase):

    __slots__ = ('block_addr', 'block_idx', 'stmt_idx', )

    def __init__(self, block_addr, block_idx, stmt_idx):
        self.block_addr = block_addr
        self.block_idx = block_idx
        self.stmt_idx = stmt_idx

    def __repr__(self):
        return f"Loc: Statement@{self.block_addr:x}.{self.block_idx}-{self.stmt_idx}"


class ExpressionLocation(LocationBase):

    __slots__ = ('block_addr', 'block_idx', 'stmt_idx', 'expr_idx', )

    def __init__(self, block_addr, block_idx, stmt_idx, expr_idx):
        self.block_addr = block_addr
        self.block_idx = block_idx
        self.stmt_idx = stmt_idx
        self.expr_idx = expr_idx

    def __repr__(self):
        return f"Loc: Expression@{self.block_addr:x}.{self.block_idx}-{self.stmt_idx}[{self.expr_idx}]"


class ConditionLocation(LocationBase):

    __slots__ = ('node_addr', )

    def __init__(self, cond_node_addr):
        self.node_addr = cond_node_addr

    def __repr__(self):
        return f"Loc: ConditionNode@{self.node_addr:x}"


class ConditionalBreakLocation(LocationBase):

    __slots__ = ('node_addr', )

    def __init__(self, node_addr):
        self.node_addr = node_addr

    def __repr__(self):
        return f"Loc: ConditionalBreakNode@{self.node_addr:x}"


class ExpressionUseFinder(AILBlockWalker):
    def __init__(self):
        super().__init__()
        self.uses = defaultdict(set)

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Optional[Statement],
                     block: Optional[Block]) -> Any:
        if isinstance(expr, ailment.Register) and expr.variable is not None:
            if not (isinstance(stmt, ailment.Stmt.Assignment) and stmt.dst is expr):
                if block is not None:
                    self.uses[expr.variable].add((expr, ExpressionLocation(block.addr, block.idx, stmt_idx, expr_idx)))
                else:
                    self.uses[expr.variable].add((expr, None))
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionCounter(SequenceWalker):
    """
    Find all expressions that are assigned once and only used once.
    """
    def __init__(self, node, variable_manager):
        handlers = {
            ConditionalBreakNode: self._handle_ConditionalBreak,
            ConditionNode: self._handle_Condition,
            LoopNode: self._handle_Loop,
            ailment.Block: self._handle_Block,
        }

        self.assignments = defaultdict(set)
        self.uses = { }
        self._variable_manger: 'VariableManagerInternal' = variable_manager

        super().__init__(handlers)
        self.walk(node)

    def _u(self, v) -> Optional['SimVariable']:
        """
        Get unified variable for a given variable.
        """

        return self._variable_manger.unified_variable(v)

    def _handle_Block(self, node: ailment.Block, **kwargs):
        # find assignments
        for idx, stmt in enumerate(node.statements):
            if isinstance(stmt, ailment.Stmt.Assignment):
                if isinstance(stmt.dst, ailment.Expr.Register) and stmt.dst.variable is not None:
                    u = self._u(stmt.dst.variable)
                    if u is not None:
                        # dependency
                        dependencies = [ ]
                        if isinstance(stmt.src, ailment.Expr.Register):
                            dep_u = self._u(stmt.src.variable)
                            if dep_u is not None:
                                dependencies.append(dep_u)
                        # TODO: Replace the above logic with an expression walker
                        self.assignments[u].add((stmt.src,
                                                 tuple(dependencies),
                                                 StatementLocation(node.addr, node.idx, idx)))
            if (isinstance(stmt, ailment.Stmt.Call)
                    and isinstance(stmt.ret_expr, ailment.Expr.Register)
                    and stmt.ret_expr.variable is not None):
                u = self._u(stmt.ret_expr.variable)
                if u is not None:
                    self.assignments[u].add((stmt,
                                             (),
                                             StatementLocation(node.addr, node.idx, idx)))

        # walk the block and find uses of variables
        use_finder = ExpressionUseFinder()
        use_finder.walk(node)

        for v, content in use_finder.uses.items():
            u = self._u(v)
            if u is not None:
                if u not in self.uses:
                    self.uses[u] = set()
                self.uses[u] |= content

    def _collect_uses(self, expr: Expression, loc: LocationBase):
        use_finder = ExpressionUseFinder()
        use_finder.walk_expression(expr, stmt_idx=-1)

        for var, uses in use_finder.uses.items():
            u = self._u(var)
            if u is None:
                continue
            for use in uses:
                if u not in self.uses:
                    self.uses[u] = set()
                self.uses[u].add((use[0], loc))

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        # collect uses on the condition expression
        self._collect_uses(node.condition, ConditionalBreakLocation(node.addr))
        return super()._handle_ConditionalBreak(node, **kwargs)

    def _handle_Condition(self, node: ConditionNode, **kwargs):
        # collect uses on the condition expression
        self._collect_uses(node.condition, ConditionLocation(node.addr))
        return super()._handle_Condition(node, **kwargs)

    def _handle_Loop(self, node: LoopNode, **kwargs):
        # collect uses on the condition expression
        if node.initializer is not None:
            self._collect_uses(node.initializer, ConditionLocation(node.addr))
        if node.iterator is not None:
            self._collect_uses(node.iterator, ConditionLocation(node.addr))
        if node.condition is not None:
            self._collect_uses(node.condition, ConditionLocation(node.addr))
        return super()._handle_Loop(node, **kwargs)


class ExpressionReplacer(AILBlockWalker):
    def __init__(self, assignments: Dict, uses: Dict):
        super().__init__()
        self._assignments = assignments
        self._uses = uses

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Optional[Statement],
                     block: Optional[Block]) -> Any:
        if isinstance(expr, ailment.Register) and expr.variable is not None and expr.variable in self._uses:
            replace_with, _ = self._assignments[expr.variable]
            return replace_with
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionFolder(SequenceWalker):
    def __init__(self, assignments: Dict, uses: Dict, node):

        handlers = {
            ailment.Block: self._handle_Block,
            ConditionNode: self._handle_Condition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
        }

        super().__init__(handlers)
        self._assignments = assignments
        self._uses = uses
        self.walk(node)

    def _handle_Block(self, node: ailment.Block, **kwargs):
        # Walk the block to remove each assignment and replace uses of each variable
        new_stmts = [ ]
        for stmt in node.statements:
            if isinstance(stmt, ailment.Stmt.Assignment):
                if isinstance(stmt.dst, ailment.Expr.Register) and stmt.dst.variable is not None:
                    if stmt.dst.variable in self._assignments:
                        # remove this statement
                        continue
            if (isinstance(stmt, ailment.Stmt.Call)
                    and isinstance(stmt.ret_expr, ailment.Expr.Register)
                    and stmt.ret_expr.variable is not None
                    and stmt.ret_expr.variable in self._assignments):
                # remove this statement
                continue
            new_stmts.append(stmt)
        node.statements = new_stmts

        # Walk the block to replace the use of each variable
        replacer = ExpressionReplacer(self._assignments, self._uses)
        replacer.walk(node)

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses)
        r = replacer.walk_expression(node.condition)
        if r is not None and r is not node.condition:
            node.condition = r
        return super()._handle_ConditionalBreak(node, **kwargs)

    def _handle_Condition(self, node: ConditionNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses)
        r = replacer.walk_expression(node.condition)
        if r is not None and r is not node.condition:
            node.condition = r
        return super()._handle_Condition(node, **kwargs)

    def _handle_Loop(self, node: LoopNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses)

        # iterator
        if node.iterator is not None:
            r = replacer.walk_expression(node.iterator)
            if r is not None and r is not node.iterator:
                node.iterator = r

        # initializer
        if node.initializer is not None:
            r = replacer.walk_expression(node.initializer)
            if r is not None and r is not node.initializer:
                node.initializer = r

        # condition
        if node.condition is not None:
            r = replacer.walk_expression(node.condition)
            if r is not None and r is not node.condition:
                node.condition = r

        return super()._handle_Loop(node, **kwargs)

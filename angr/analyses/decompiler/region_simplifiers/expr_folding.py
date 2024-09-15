# pylint:disable=missing-class-docstring,unused-argument
from __future__ import annotations
from collections import defaultdict
from typing import Any, TYPE_CHECKING
from collections.abc import Iterable

import ailment
from ailment import Expression, Block, AILBlockWalker
from ailment.expression import ITE
from ailment.statement import Statement, Assignment, Call

from angr.utils.ail import is_phi_assignment
from ..sequence_walker import SequenceWalker
from ..structuring.structurer_nodes import (
    ConditionNode,
    ConditionalBreakNode,
    LoopNode,
    CascadingConditionNode,
    SwitchCaseNode,
)

if TYPE_CHECKING:
    from angr.sim_variable import SimVariable
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from ailment.expression import MultiStatementExpression


class LocationBase:
    __slots__ = ()


class StatementLocation(LocationBase):
    __slots__ = (
        "block_addr",
        "block_idx",
        "stmt_idx",
    )

    def __init__(self, block_addr, block_idx, stmt_idx):
        self.block_addr = block_addr
        self.block_idx = block_idx
        self.stmt_idx = stmt_idx

    def __repr__(self):
        return f"Loc: Statement@{self.block_addr:x}.{self.block_idx}-{self.stmt_idx}"

    def __hash__(self):
        return hash((StatementLocation, self.block_addr, self.block_idx, self.stmt_idx))

    def __eq__(self, other):
        return (
            isinstance(other, StatementLocation)
            and self.block_addr == other.block_addr
            and self.block_idx == other.block_idx
            and self.stmt_idx == other.stmt_idx
        )

    def copy(self):
        return StatementLocation(self.block_addr, self.block_idx, self.stmt_idx)


class ExpressionLocation(LocationBase):
    __slots__ = (
        "block_addr",
        "block_idx",
        "stmt_idx",
        "expr_idx",
    )

    def __init__(self, block_addr, block_idx, stmt_idx, expr_idx):
        self.block_addr = block_addr
        self.block_idx = block_idx
        self.stmt_idx = stmt_idx
        self.expr_idx = expr_idx

    def __repr__(self):
        return f"Loc: Expression@{self.block_addr:x}.{self.block_idx}-{self.stmt_idx}[{self.expr_idx}]"

    def statement_location(self) -> StatementLocation:
        return StatementLocation(self.block_addr, self.block_idx, self.stmt_idx)

    def __hash__(self):
        return hash((ExpressionLocation, self.block_addr, self.block_idx, self.stmt_idx, self.expr_idx))

    def __eq__(self, other):
        return (
            isinstance(other, ExpressionLocation)
            and self.block_addr == other.block_addr
            and self.block_idx == other.block_idx
            and self.stmt_idx == other.stmt_idx
            and self.expr_idx == other.expr_idx
        )


class ConditionLocation(LocationBase):
    __slots__ = (
        "node_addr",
        "case_idx",
    )

    def __init__(self, cond_node_addr, case_idx: int | None = None):
        self.node_addr = cond_node_addr
        self.case_idx = case_idx

    def __repr__(self):
        return f"Loc: ConditionNode@{self.node_addr:x}.{self.case_idx}"

    def __hash__(self):
        return hash((ConditionLocation, self.node_addr, self.case_idx))

    def __eq__(self, other):
        return (
            isinstance(other, ConditionLocation)
            and self.node_addr == other.node_addr
            and self.case_idx == other.case_idx
        )


class ConditionalBreakLocation(LocationBase):
    __slots__ = ("node_addr",)

    def __init__(self, node_addr):
        self.node_addr = node_addr

    def __repr__(self):
        return f"Loc: ConditionalBreakNode@{self.node_addr:x}"

    def __hash__(self):
        return hash((ConditionalBreakLocation, self.node_addr))

    def __eq__(self, other):
        return isinstance(other, ConditionalBreakLocation) and self.node_addr == other.node_addr


class MultiStatementExpressionAssignmentFinder(AILBlockWalker):
    """
    Process statements in MultiStatementExpression objects and find assignments.
    """

    def __init__(self, stmt_handler):
        super().__init__()
        self._stmt_handler = stmt_handler

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        for idx, stmt_ in enumerate(expr.stmts):
            self._stmt_handler(idx, stmt_, block)
        return super()._handle_MultiStatementExpression(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionUseFinder(AILBlockWalker):
    """
    Find where each variable is used.

    Additionally, determine if the expression being walked has load expressions inside. Such expressions can only be
    safely folded if there are no Store statements between the expression defining location and its use sites. For
    example, we can only safely fold variable assignments that use Load() when there are no Store()s between the
    assignment and its use site. Otherwise, the loaded expression may get updated later by a Store() statement.

    Here is a real AIL block:

    .. code-block:: none

        v16 = ((int)v23->field_5) + 1 & 255;
        v23->field_5 = ((char)(((int)v23->field_5) + 1 & 255));
        v13 = printf("Recieved packet %d for connection with %d\\n", v16, a0 & 255);

    In this case, folding v16 into the last printf() expression would be incorrect, since v23->field_5 is updated by
    the second statement.
    """

    __slots__ = (
        "uses",
        "has_load",
    )

    def __init__(self):
        super().__init__()
        self.uses: defaultdict[SimVariable, set[tuple[Expression, ExpressionLocation | None]]] = defaultdict(set)
        self.has_load = False

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, ailment.Expr.VirtualVariable) and expr.was_reg and expr.variable is not None:
            if not (isinstance(stmt, ailment.Stmt.Assignment) and stmt.dst is expr):
                if block is not None:
                    self.uses[expr.variable].add((expr, ExpressionLocation(block.addr, block.idx, stmt_idx, expr_idx)))
                else:
                    self.uses[expr.variable].add((expr, None))
            return None
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: ailment.Expr.Load, stmt_idx: int, stmt: Statement, block: Block | None):
        self.has_load = True
        return super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionCounter(SequenceWalker):
    """
    Find all expressions that are assigned once and only used once.
    """

    def __init__(self, node, variable_manager):
        handlers = {
            ConditionalBreakNode: self._handle_ConditionalBreak,
            ConditionNode: self._handle_Condition,
            LoopNode: self._handle_Loop,
            SwitchCaseNode: self._handle_SwitchCase,
            ailment.Block: self._handle_Block,
        }

        # each element in the set is a tuple of (source of the assignment statement, a tuple of unified variables that
        # the current assignment depends on, StatementLocation of the assignment statement, a Boolean variable that
        # indicates if ExpressionUseFinder has succeeded or not)
        self.assignments: defaultdict[Any, set[tuple]] = defaultdict(set)
        self.uses: dict[SimVariable, set[tuple[Expression, LocationBase | None]]] = {}
        self._variable_manager: VariableManagerInternal = variable_manager

        super().__init__(handlers)
        self.walk(node)

    def _u(self, v) -> SimVariable | None:
        """
        Get unified variable for a given variable.
        """

        return self._variable_manager.unified_variable(v)

    def _handle_Statement(self, idx: int, stmt: ailment.Stmt, node: ailment.Block | LoopNode):
        if isinstance(stmt, ailment.Stmt.Assignment):
            if is_phi_assignment(stmt):
                return
            if (
                isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                and stmt.dst.was_reg
                and stmt.dst.variable is not None
            ):
                u = self._u(stmt.dst.variable)
                if u is not None:
                    # dependency
                    dependency_finder = ExpressionUseFinder()
                    dependency_finder.walk_expression(stmt.src)
                    dependencies = tuple({self._u(v) for v in dependency_finder.uses})
                    self.assignments[u].add(
                        (
                            stmt.src,
                            dependencies,
                            StatementLocation(node.addr, node.idx if isinstance(node, ailment.Block) else None, idx),
                            dependency_finder.has_load,
                        )
                    )
        if (
            isinstance(stmt, ailment.Stmt.Call)
            and isinstance(stmt.ret_expr, ailment.Expr.VirtualVariable)
            and stmt.ret_expr.was_reg
            and stmt.ret_expr.variable is not None
        ):
            u = self._u(stmt.ret_expr.variable)
            if u is not None:
                dependency_finder = ExpressionUseFinder()
                dependency_finder.walk_expression(stmt)
                dependencies = tuple({self._u(v) for v in dependency_finder.uses})
                self.assignments[u].add(
                    (
                        stmt,
                        dependencies,
                        StatementLocation(node.addr, node.idx if isinstance(node, ailment.Block) else None, idx),
                        dependency_finder.has_load,
                    )
                )

    def _handle_Block(self, node: ailment.Block, **kwargs):
        # find assignments
        for idx, stmt in enumerate(node.statements):
            self._handle_Statement(idx, stmt, node)

        # walk the block and find uses of variables
        use_finder = ExpressionUseFinder()
        use_finder.walk(node)

        for v, content in use_finder.uses.items():
            u = self._u(v)
            if u is not None:
                if u not in self.uses:
                    self.uses[u] = set()
                self.uses[u] |= content

    def _collect_assignments(self, expr: ailment.Expr, node) -> None:
        finder = MultiStatementExpressionAssignmentFinder(self._handle_Statement)
        finder.walk_expression(expr, None, None, node)

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
        self._collect_assignments(node.condition, node)
        self._collect_uses(node.condition, ConditionalBreakLocation(node.addr))
        return super()._handle_ConditionalBreak(node, **kwargs)

    def _handle_Condition(self, node: ConditionNode, **kwargs):
        # collect uses on the condition expression
        self._collect_assignments(node.condition, node)
        self._collect_uses(node.condition, ConditionLocation(node.addr))
        return super()._handle_Condition(node, **kwargs)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        for idx, (condition, _) in enumerate(node.condition_and_nodes):
            self._collect_assignments(condition, node)
            self._collect_uses(condition, ConditionLocation(node.addr, idx))
        return super()._handle_CascadingCondition(node, **kwargs)

    def _handle_Loop(self, node: LoopNode, **kwargs):
        # collect uses on the condition expression
        if node.initializer is not None:
            self._collect_uses(node.initializer, ConditionLocation(node.addr))
        if node.iterator is not None:
            self._collect_uses(node.iterator, ConditionLocation(node.addr))
        if node.condition is not None:
            self._collect_assignments(node.condition, node)
            self._collect_uses(node.condition, ConditionLocation(node.addr))
        return super()._handle_Loop(node, **kwargs)

    def _handle_SwitchCase(self, node: SwitchCaseNode, **kwargs):
        self._collect_uses(node.switch_expr, ConditionLocation(node.addr))
        return super()._handle_SwitchCase(node, **kwargs)


class ExpressionReplacer(AILBlockWalker):
    def __init__(self, assignments: dict, uses: dict, variable_manager):
        super().__init__()
        self._assignments = assignments
        self._uses = uses
        self._variable_manager: VariableManagerInternal = variable_manager

    def _u(self, v) -> SimVariable | None:
        """
        Get unified variable for a given variable.
        """
        return self._variable_manager.unified_variable(v)

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        changed = False
        new_statements = []
        for idx, stmt_ in enumerate(expr.stmts):
            if (
                isinstance(stmt_, Assignment)
                and isinstance(stmt_.dst, ailment.Expr.VirtualVariable)
                and stmt_.dst.was_reg
                and stmt_.dst.variable is not None
            ) and stmt_.dst.variable in self._assignments:
                # remove this statement
                changed = True
                continue

            new_stmt = self._handle_stmt(idx, stmt_, None)
            if new_stmt is not None and new_stmt is not stmt_:
                changed = True
                if isinstance(new_stmt, Assignment) and new_stmt.src.likes(new_stmt.dst):
                    # this statement is simplified into reg = reg. ignore it
                    continue
                new_statements.append(new_stmt)
            else:
                new_statements.append(stmt_)

        new_expr = self._handle_expr(0, expr.expr, stmt_idx, stmt, block)
        if new_expr is not None and new_expr is not expr.expr:
            changed = True
        else:
            new_expr = expr.expr

        if changed:
            if not new_statements:
                # it is no longer a multi-statement expression
                return new_expr
            expr_ = expr.copy()
            expr_.expr = new_expr
            expr_.stmts = new_statements
            return expr_
        return None

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None):
        # override the base handler and make sure we do not replace .dst with a Call expression or an ITE expression
        changed = False

        dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        if dst is not None and dst is not stmt.dst and not isinstance(dst, (Call, ITE)):
            changed = True
        else:
            dst = stmt.dst

        src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        if src is not None and src is not stmt.src:
            changed = True
        else:
            src = stmt.src

        if changed:
            new_stmt = Assignment(stmt.idx, dst, src, **stmt.tags)
            if block is not None:
                # update the statement directly in the block
                block.statements[stmt_idx] = new_stmt
            return new_stmt
        return None

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Any:
        if isinstance(expr, ailment.Expr.VirtualVariable) and expr.was_reg and expr.variable is not None:
            unified_var = self._u(expr.variable)
            if unified_var in self._uses:
                replace_with, _ = self._assignments[unified_var]
                return replace_with
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionFolder(SequenceWalker):
    def __init__(self, assignments: dict, uses: dict, node, variable_manager):
        handlers = {
            ailment.Block: self._handle_Block,
            ConditionNode: self._handle_Condition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            SwitchCaseNode: self._handle_SwitchCase,
        }

        super().__init__(handlers)
        self._assignments = assignments
        self._uses = uses
        self._variable_manager = variable_manager
        self.walk(node)

    def _u(self, v) -> SimVariable | None:
        """
        Get unified variable for a given variable.
        """
        return self._variable_manager.unified_variable(v)

    def _handle_Block(self, node: ailment.Block, **kwargs):
        # Walk the block to remove each assignment and replace uses of each variable
        new_stmts = []
        for stmt in node.statements:
            if (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.dst, ailment.Expr.VirtualVariable)
                and stmt.dst.was_reg
                and stmt.dst.variable is not None
            ):
                unified_var = self._u(stmt.dst.variable)
                if unified_var in self._assignments:
                    # remove this statement
                    continue
            if (
                isinstance(stmt, ailment.Stmt.Call)
                and isinstance(stmt.ret_expr, ailment.Expr.VirtualVariable)
                and stmt.ret_expr.was_reg
                and stmt.ret_expr.variable is not None
            ):
                unified_var = self._u(stmt.ret_expr.variable)
                if unified_var in self._assignments:
                    # remove this statement
                    continue
            new_stmts.append(stmt)
        node.statements = new_stmts

        # Walk the block to replace the use of each variable
        replacer = ExpressionReplacer(self._assignments, self._uses, self._variable_manager)
        replacer.walk(node)

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses, self._variable_manager)
        r = replacer.walk_expression(node.condition)
        if r is not None and r is not node.condition:
            node.condition = r
        return super()._handle_ConditionalBreak(node, **kwargs)

    def _handle_Condition(self, node: ConditionNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses, self._variable_manager)
        r = replacer.walk_expression(node.condition)
        if r is not None and r is not node.condition:
            node.condition = r
        return super()._handle_Condition(node, **kwargs)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses, self._variable_manager)
        for idx in range(len(node.condition_and_nodes)):  # pylint:disable=consider-using-enumerate
            cond, _ = node.condition_and_nodes[idx]
            r = replacer.walk_expression(cond)
            if r is not None and r is not cond:
                node.condition_and_nodes[idx] = (r, node.condition_and_nodes[idx][1])
        return super()._handle_CascadingCondition(node, **kwargs)

    def _handle_Loop(self, node: LoopNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses, self._variable_manager)

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

    def _handle_SwitchCase(self, node: SwitchCaseNode, **kwargs):
        replacer = ExpressionReplacer(self._assignments, self._uses, self._variable_manager)

        r = replacer.walk_expression(node.switch_expr)
        if r is not None and r is not node.switch_expr:
            node.switch_expr = r

        return super()._handle_SwitchCase(node, **kwargs)


class StoreStatementFinder(SequenceWalker):
    """
    Determine if there are any Store statements between two given statements.

    This class overrides _handle_Sequence() and _handle_MultiNode() to ensure they traverse nodes from top to bottom.
    """

    def __init__(self, node, intervals: Iterable[tuple[StatementLocation, LocationBase]]):
        handlers = {
            ConditionNode: self._handle_Condition,
            CascadingConditionNode: self._handle_CascadingCondition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            ailment.Block: self._handle_Block,
        }

        self._intervals = intervals

        self._start_to_ends: defaultdict[StatementLocation, set[LocationBase]] = defaultdict(set)
        self._end_to_starts: defaultdict[LocationBase, set[StatementLocation]] = defaultdict(set)
        self.interval_to_hasstore: dict[tuple[StatementLocation, StatementLocation], bool] = {}
        for start, end in intervals:
            self._start_to_ends[start].add(end)
            self._end_to_starts[end].add(start)

        self._active_intervals = set()

        super().__init__(handlers)
        self.walk(node)

    def _handle_Sequence(self, node, **kwargs):
        i = 0
        while i < len(node.nodes):
            node_ = node.nodes[i]
            self._handle(node_, parent=node, index=i)
            i += 1

    def _handle_MultiNode(self, node, **kwargs):
        i = 0
        while i < len(node.nodes):
            node_ = node.nodes[i]
            self._handle(node_, parent=node, index=i)
            i += 1

    def _handle_Block(self, node: ailment.Block, **kwargs):
        stmt_loc = StatementLocation(node.addr, node.idx, None)
        for idx, stmt in enumerate(node.statements):
            stmt_loc.stmt_idx = idx
            if stmt_loc in self._start_to_ends:
                for end in self._start_to_ends[stmt_loc]:
                    self._active_intervals.add((stmt_loc.copy(), end))
            if stmt_loc in self._end_to_starts:
                for start in self._end_to_starts[stmt_loc]:
                    self._active_intervals.discard((start, stmt_loc))
            if isinstance(stmt, ailment.Stmt.Store):
                for interval in self._active_intervals:
                    self.interval_to_hasstore[interval] = True

    def _handle_Condition(self, node, **kwargs):
        cond_loc = ConditionLocation(node.addr)
        if cond_loc in self._end_to_starts:
            for start in self._end_to_starts[cond_loc]:
                self._active_intervals.discard((start, cond_loc))
        super()._handle_Condition(node, **kwargs)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        cond_loc = ConditionLocation(node.addr, None)
        for idx in range(len(node.condition_and_nodes)):
            cond_loc.case_idx = idx
            if cond_loc in self._end_to_starts[cond_loc]:
                for start in self._end_to_starts[cond_loc]:
                    self._active_intervals.discard((start, cond_loc))
        super()._handle_CascadingCondition(node, **kwargs)

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        cond_break_loc = ConditionalBreakLocation(node.addr)
        if cond_break_loc in self._end_to_starts:
            for start in self._end_to_starts[cond_break_loc]:
                self._active_intervals.discard((start, cond_break_loc))
        super()._handle_ConditionalBreak(node, **kwargs)

    def has_store(self, start: StatementLocation, end: StatementLocation) -> bool:
        return self.interval_to_hasstore.get((start, end), False)

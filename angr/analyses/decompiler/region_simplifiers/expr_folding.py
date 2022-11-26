# pylint:disable=missing-class-docstring,unused-argument
from collections import defaultdict
from typing import Optional, Any, Dict, Set, Tuple, Iterable, DefaultDict, TYPE_CHECKING

import ailment
from ailment import Expression, Block
from ailment.statement import Statement, Assignment, Call

from ..ailblock_walker import AILBlockWalker
from ..sequence_walker import SequenceWalker
from ..structuring.structurer_nodes import ConditionNode, ConditionalBreakNode, LoopNode, CascadingConditionNode

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

    def __hash__(self):
        return hash((StatementLocation, self.block_addr, self.block_idx, self.stmt_idx))

    def __eq__(self, other):
        return isinstance(other, StatementLocation) and \
            self.block_addr == other.block_addr and \
            self.block_idx == other.block_idx and \
            self.stmt_idx == other.stmt_idx

    def copy(self):
        return StatementLocation(self.block_addr, self.block_idx, self.stmt_idx)


class ExpressionLocation(LocationBase):

    __slots__ = ('block_addr', 'block_idx', 'stmt_idx', 'expr_idx', )

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
        return isinstance(other, ExpressionLocation) and \
                self.block_addr == other.block_addr and \
                self.block_idx == other.block_idx and \
                self.stmt_idx == other.stmt_idx and \
                self.expr_idx == other.expr_idx


class ConditionLocation(LocationBase):

    __slots__ = ('node_addr', 'case_idx', )

    def __init__(self, cond_node_addr, case_idx: Optional[int]=None):
        self.node_addr = cond_node_addr
        self.case_idx = case_idx

    def __repr__(self):
        return f"Loc: ConditionNode@{self.node_addr:x}.{self.case_idx}"

    def __hash__(self):
        return hash((ConditionLocation, self.node_addr, self.case_idx))

    def __eq__(self, other):
        return isinstance(other, ConditionLocation) and \
                self.node_addr == other.node_addr and \
                self.case_idx == other.case_idx


class ConditionalBreakLocation(LocationBase):

    __slots__ = ('node_addr', )

    def __init__(self, node_addr):
        self.node_addr = node_addr

    def __repr__(self):
        return f"Loc: ConditionalBreakNode@{self.node_addr:x}"

    def __hash__(self):
        return hash((ConditionalBreakLocation, self.node_addr))

    def __eq__(self, other):
        return isinstance(other, ConditionalBreakLocation) and \
                self.node_addr == other.node_addr


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

    __slots__ = ('uses', 'has_load', )

    def __init__(self):
        super().__init__()
        self.uses = defaultdict(set)
        self.has_load = False

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

    def _handle_Load(self, expr_idx: int, expr: ailment.Expr.Load, stmt_idx: int, stmt: Statement,
                     block: Optional[Block]):
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
            ailment.Block: self._handle_Block,
        }

        # each element in the set is a tuple of (source of the assignment statement, a tuple of unified variables that
        # the current assignment depends on, StatementLocation of the assignment statement, a Boolean variable that
        # indicates if ExpressionUseFinder has succeeded or not)
        self.assignments: DefaultDict[Any,Set[Tuple]] = defaultdict(set)
        self.uses = { }
        self._variable_manager: 'VariableManagerInternal' = variable_manager

        super().__init__(handlers)
        self.walk(node)

    def _u(self, v) -> Optional['SimVariable']:
        """
        Get unified variable for a given variable.
        """

        return self._variable_manager.unified_variable(v)

    def _handle_Block(self, node: ailment.Block, **kwargs):
        # find assignments
        for idx, stmt in enumerate(node.statements):
            if isinstance(stmt, ailment.Stmt.Assignment):
                if isinstance(stmt.dst, ailment.Expr.Register) and stmt.dst.variable is not None:
                    u = self._u(stmt.dst.variable)
                    if u is not None:
                        # dependency
                        dependency_finder = ExpressionUseFinder()
                        dependency_finder.walk_expression(stmt.src)
                        dependencies = tuple(set(self._u(v) for v in dependency_finder.uses))
                        self.assignments[u].add((stmt.src,
                                                 dependencies,
                                                 StatementLocation(node.addr, node.idx, idx),
                                                 dependency_finder.has_load))
            if (isinstance(stmt, ailment.Stmt.Call)
                    and isinstance(stmt.ret_expr, ailment.Expr.Register)
                    and stmt.ret_expr.variable is not None):
                u = self._u(stmt.ret_expr.variable)
                if u is not None:
                    dependency_finder = ExpressionUseFinder()
                    dependency_finder.walk_expression(stmt)
                    dependencies = tuple(set(self._u(v) for v in dependency_finder.uses))
                    self.assignments[u].add((stmt,
                                             dependencies,
                                             StatementLocation(node.addr, node.idx, idx),
                                             dependency_finder.has_load))

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

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        for idx, (condition, _) in enumerate(node.condition_and_nodes):
            self._collect_uses(condition, ConditionLocation(node.addr, idx))
        return super()._handle_CascadingCondition(node, **kwargs)

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
    def __init__(self, assignments: Dict, uses: Dict, variable_manager):
        super().__init__()
        self._assignments = assignments
        self._uses = uses
        self._variable_manager: 'VariableManagerInternal' = variable_manager

    def _u(self, v) -> Optional['SimVariable']:
        """
        Get unified variable for a given variable.
        """
        return self._variable_manager.unified_variable(v)

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Optional[Block]):
        # override the base handler and make sure we do not replace .dst with a Call expression
        changed = False

        dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        if dst is not None and dst is not stmt.dst and not isinstance(dst, Call):
            changed = True
        else:
            dst = stmt.dst

        src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        if src is not None and src is not stmt.src:
            changed = True
        else:
            src = stmt.src

        if changed:
            # update the statement directly in the block
            new_stmt = Assignment(stmt.idx, dst, src, **stmt.tags)
            block.statements[stmt_idx] = new_stmt

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Optional[Statement],
                     block: Optional[Block]) -> Any:
        if isinstance(expr, ailment.Register) and expr.variable is not None:
            unified_var = self._u(expr.variable)
            if unified_var in self._uses:
                replace_with, _ = self._assignments[unified_var]
                return replace_with
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class ExpressionFolder(SequenceWalker):
    def __init__(self, assignments: Dict, uses: Dict, node, variable_manager):

        handlers = {
            ailment.Block: self._handle_Block,
            ConditionNode: self._handle_Condition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
        }

        super().__init__(handlers)
        self._assignments = assignments
        self._uses = uses
        self._variable_manager = variable_manager
        self.walk(node)

    def _u(self, v) -> Optional['SimVariable']:
        """
        Get unified variable for a given variable.
        """
        return self._variable_manager.unified_variable(v)

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
                    and stmt.ret_expr.variable is not None):
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
        for idx in range(len(node.condition_and_nodes)):
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


class StoreStatementFinder(SequenceWalker):
    """
    Determine if there are any Store statements between two given statements.
    """
    def __init__(self, node, intervals: Iterable[Tuple[StatementLocation,LocationBase]]):
        handlers = {
            ConditionNode: self._handle_Condition,
            CascadingConditionNode: self._handle_CascadingCondition,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            ailment.Block: self._handle_Block,
        }

        self._intervals = intervals

        self._start_to_ends: DefaultDict[StatementLocation,Set[LocationBase]] = defaultdict(set)
        self._end_to_starts: DefaultDict[LocationBase,Set[StatementLocation]] = defaultdict(set)
        self.interval_to_hasstore: Dict[Tuple[StatementLocation,StatementLocation],bool] = { }
        for start, end in intervals:
            self._start_to_ends[start].add(end)
            self._end_to_starts[end].add(start)

        self._active_intervals = set()

        super().__init__(handlers)
        self.walk(node)

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

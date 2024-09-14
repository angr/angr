# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
import logging

from angr.analyses import ForwardAnalysis, visitors
from ..block import SootBlockNode
from ..errors import AngrLoopAnalysisError
from . import register_analysis
from .analysis import Analysis


l = logging.getLogger(name=__name__)


class VariableTypes:
    Iterator = "Iterator"
    HasNext = "HasNext"
    Next = "Next"


class AnnotatedVariable:
    __slots__ = ["variable", "type"]

    def __init__(self, variable, type_):
        self.variable = variable
        self.type = type_

    def __repr__(self):
        return f"{self.variable}//{self.type}"

    def __eq__(self, other):
        return type(other) is AnnotatedVariable and other.type == self.type and other.variable == self.variable


class Condition:
    Equal = "=="
    NotEqual = "!="

    def __init__(self, op, val0, val1):
        self.op = op
        self.val0 = val0
        self.val1 = val1

    def __repr__(self):
        return f"{self.val0} {self.op} {self.val1}"

    @classmethod
    def from_opstr(cls, opstr):
        mapping = {
            "eq": cls.Equal,
            "==": cls.Equal,
            "ne": cls.NotEqual,
            "!=": cls.NotEqual,
        }

        return mapping.get(opstr)


class SootBlockProcessor:
    def __init__(self, state, block, loop, defuse):
        self.state = state
        self.block = block
        self.loop = loop
        self.defuse = defuse

    def process(self):
        if not isinstance(self.block, SootBlockNode):
            raise AngrLoopAnalysisError(f"Got an unexpected type of block {type(self.block)}.")

        if not self.block.stmts:
            return None

        for stmt in self.block.stmts:
            func_name = f"_handle_{stmt.__class__.__name__}"

            if hasattr(self, func_name):
                getattr(self, func_name)(stmt)

        return self.state

    def _stmt_inside_loop(self, stmt_idx):
        """
        Test whether a statement is inside the loop body or not.

        :param stmt_idx:
        :return:
        """

        # TODO: This is slow. Fix the performance issue

        return any(node.addr.stmt_idx <= stmt_idx < node.addr.stmt_idx + node.size for node in self.loop.body_nodes)

    def _expr(self, expr):
        func_name = f"_handle_{expr.__class__.__name__}"

        if hasattr(self, func_name):
            return getattr(self, func_name)(expr)

        return expr

    #
    # Statement handlers
    #

    def _handle_AssignStmt(self, stmt):
        left_op, right_op = stmt.left_op, stmt.right_op

        expr = self._expr(right_op)
        if expr is not None:
            try:
                from pysoot.sootir.soot_value import SootLocal
            except ImportError:
                l.error("Please install PySoot before analyzing Java byte code.")
                raise
            if isinstance(left_op, SootLocal):
                # Log a def for the local variable
                self.state.locals[left_op.name] = expr

    def _handle_IfStmt(self, stmt):
        target = stmt.target

        # is it jumping outside the loop?
        if not self._stmt_inside_loop(target):
            cond = Condition(
                Condition.from_opstr(stmt.condition.op),
                self._expr(stmt.condition.value1),
                self._expr(stmt.condition.value2),
            )

            self.state.add_loop_exit_stmt(stmt.label, condition=cond)

    #
    # Expression handlers
    #

    def _handle_SootLocal(self, expr):
        local_name = expr.name

        # First try state.locals
        try:
            return self.state.locals[local_name]
        except KeyError:
            pass

        # Then try defuse graph
        try:
            def_ = self.defuse.defs[local_name]
            expr = def_.evaluated
        except KeyError:
            pass

        return expr

    def _handle_SootIntConstant(self, expr):
        return expr.value

    def _handle_SootInterfaceInvokeExpr(self, expr):
        full_method = expr.class_name + "." + expr.method_name

        mapping = {
            "java.util.Set.iterator": VariableTypes.Iterator,
            "java.util.Iterator.hasNext": VariableTypes.HasNext,
            "java.util.Iterator.next": VariableTypes.Next,
        }

        base_var = self._expr(expr.base)

        if base_var is None:
            return None

        # Try to annotate the variable when applicable
        try:
            try:
                from pysoot.sootir.soot_value import SootValue
            except ImportError:
                l.error("Please install PySoot before analyzing Java byte code.")
                raise

            var_type = mapping[full_method]

            if isinstance(base_var, (SootValue, AnnotatedVariable)):
                return AnnotatedVariable(base_var, var_type)

        except KeyError:
            pass

        return None


class LoopAnalysisState:
    def __init__(self, block):
        self.block = block

        self.induction_variables = {}
        self.locals = {}

        self.loop_exit_stmts = set()

    def __repr__(self):
        return f"<LoopAnalysisState {self.block.addr}>"

    def copy(self):
        state = LoopAnalysisState(block=self.block)

        state.induction_variables = self.induction_variables.copy()
        state.locals = self.locals.copy()
        state.loop_exit_stmts = self.loop_exit_stmts.copy()

        return state

    def merge(self, state):
        s = self.copy()

        # TODO: Induction variables

        s.locals.update(state.locals)
        s.loop_exit_stmts |= state.loop_exit_stmts

        return s

    def add_loop_exit_stmt(self, stmt_idx, condition=None):
        self.loop_exit_stmts.add((condition, stmt_idx))


class LoopAnalysis(ForwardAnalysis, Analysis):
    """
    Analyze a loop and recover important information about the loop (e.g., invariants, induction variables) in a static
    manner.
    """

    def __init__(self, loop, defuse):
        visitor = visitors.LoopVisitor(loop)
        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False, graph_visitor=visitor)

        self.loop = loop
        self.defuse = defuse
        self._traversed = set()
        self._last_state = None

        self.loop_exit_stmts = None
        self.locals = None
        self.bounded = None  # Whether this loop is bounded

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):
        return LoopAnalysisState(node)

    def _merge_states(self, node, *states):
        merged = states[0]
        for other in states[1:]:
            if other is not None:
                merged = merged.merge(other)
        return merged

    def _run_on_node(self, node, state):
        if node in self._traversed:
            return False, state

        self._traversed.add(node)

        state = state.copy()

        processor = SootBlockProcessor(state, node, self.loop, self.defuse)
        state = processor.process()

        self._last_state = state

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        self.loop_exit_stmts = self._last_state.loop_exit_stmts
        self.locals = self._last_state.locals

        self._last_state = None

        # Is it bounded?
        self.bounded = self._is_bounded()

    def _is_bounded(self):
        """
        Checks whether this loop is bounded. We basically does a bunch of pattern matching.

        :return: True if this loop is bounded, False is this loop is not bounded, None otherwise (undetermined).
        :rtype: bool or None
        """

        b = self._is_bounded_iterator_based()
        if b is not None:
            return b

        # Cannot determine
        return None

    def _is_bounded_iterator_based(self):
        """
        Iterator based check.

        With respect to a certain variable/value A,
        - there must be at least one exit condition being A//Iterator//HasNext == 0
        - there must be at least one local that ticks the iterator next: A//Iterator//Next
        """

        # Condition 0
        def check_0(cond):
            return (
                isinstance(cond, Condition)
                and cond.op == Condition.Equal
                and cond.val1 == 0
                and isinstance(cond.val0, AnnotatedVariable)
                and cond.val0.type == VariableTypes.HasNext
            )

        check_0_results = [(check_0(stmt[0]), stmt[0]) for stmt in self.loop_exit_stmts]
        check_0_conds = [cond for r, cond in check_0_results if r]  # remove all False ones

        if not check_0_conds:
            return None

        the_iterator = check_0_conds[0].val0.variable

        # Condition 1
        def check_1(local):
            return (
                isinstance(local, AnnotatedVariable)
                and local.type == VariableTypes.Next
                and local.variable == the_iterator
            )

        if not any(check_1(local) for local in self.locals.values()):
            return None

        return True


register_analysis(LoopAnalysis, "LoopAnalysis")

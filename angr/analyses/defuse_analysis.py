
import copy

from pysoot.sootir.soot_value import SootLocal

from ..misc import repr_addr
from . import register_analysis
from .analysis import Analysis
from .forward_analysis import ForwardAnalysis, FunctionGraphVisitor


class Def(object):

    __slots__ = ['stmt_idx', 'expr', 'evaluated']

    def __init__(self, stmt_idx, expr, evaluated):
        self.stmt_idx = stmt_idx
        self.expr = expr
        self.evaluated = evaluated

    def __repr__(self):
        return "%d:%s" % (self.stmt_idx, self.expr)


class SootBlockProcessor(object):
    def __init__(self, state, block):
        self.state = state
        self.block = block

        self.stmt_idx = None

    def process(self):

        if not self.block.stmts:
            return

        for stmt in self.block.stmts:

            func_name = "_handle_%s" % (stmt.__class__.__name__)

            # Update the current statement index
            self.stmt_idx = stmt.label

            if hasattr(self, func_name):
                getattr(self, func_name)(stmt)

        return self.state

    def _expr(self, expr):

        func_name = "_handle_%s" % (expr.__class__.__name__)

        if hasattr(self, func_name):
            return getattr(self, func_name)(expr)

        return expr

    #
    # Statement handlers
    #

    def _handle_IdentityStmt(self, stmt):

        left_op, right_op = stmt.left_op, stmt.right_op

        # Create a use
        evaluated = self._expr(right_op)
        # Log a def
        self.state.defs[left_op.name] = Def(self.stmt_idx, right_op, evaluated)

    def _handle_AssignStmt(self, stmt):

        left_op, right_op = stmt.left_op, stmt.right_op

        # Create a use
        evaluated = self._expr(right_op)

        if isinstance(left_op, SootLocal):
            # Log a def for the local variable
            self.state.defs[left_op.name] = Def(self.stmt_idx, right_op, evaluated)

    #
    # Expression handlers
    #

    def _handle_SootLocal(self, expr):

        local_name = expr.name

        try:
            def_ = self.state.defs[local_name]
            expr = def_.evaluated
        except KeyError:
            pass

        # Log a use
        if local_name not in self.state.uses:
            self.state.uses[local_name] = set()
        self.state.uses[local_name].add(self.stmt_idx)

        return expr

    def _handle_SootInterfaceInvokeExpr(self, expr):

        expr = copy.copy(expr)
        expr.base = self._expr(expr.base)

        return expr


class DefUseState(object):
    def __init__(self, block):
        self.block = block

        self.defs = { }
        self.uses = { }

    def __repr__(self):
        return "<DefUseState %s>" % repr_addr(self.block.addr)

    def copy(self):

        state = DefUseState(block=self.block)

        state.defs = self.defs.copy()
        state.uses = self.uses.copy()

        return state

    def merge(self, state):
        s = self.copy()

        s.defs.update(state.defs)
        for var, var_uses in state.uses.items():
            if var not in s.uses:
                s.uses[var] = var_uses.copy()
            else:
                s.uses[var] |= var_uses

        return s


class DefUseAnalysis(ForwardAnalysis, Analysis):
    """
    Analyze a function and generate a def-use network for queries on def-use chains or use-def chains.
    """
    def __init__(self, func):

        visitor = FunctionGraphVisitor(func)
        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, allow_widening=False,
                                 graph_visitor=visitor)

        self.function = func
        self._traversed = set()
        self._last_state = None

        self.defs = None
        self.uses = None

        self._analyze()

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    def _initial_abstract_state(self, node):

        state = DefUseState(node)
        return state

    def _merge_states(self, node, *states):

        if states[0] is None:
            return states[1].copy()
        elif states[1] is None:
            return states[0].copy()

        return states[0].merge(states[1])

    def _run_on_node(self, node, state):

        if node in self._traversed:
            return False, state

        self._traversed.add(node)

        state = state.copy()

        processor = SootBlockProcessor(state, node)
        state = processor.process()

        self._last_state = state

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        self.defs = self._last_state.defs
        self.uses = self._last_state.uses

        self._last_state = None


register_analysis(DefUseAnalysis, 'DefUseAnalysis')

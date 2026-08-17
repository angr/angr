import logging

import ailment
from ailment.statement import Assignment, Call, ConditionalJump, DirtyStatement, Jump, Label, Store

from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(__name__)


class RedundantRejoinBranchRemover(OptimizationPass):
    """
    Remove degenerate if-regions where one branch arm only repeats statements that
    already executed in the conditional parent, then rejoins the other branch.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove redundant one-sided rejoin branches"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, max_updates=20, **kwargs):
        super().__init__(func, **kwargs)
        self._max_updates = max_updates
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        changed = False

        for _ in range(self._max_updates):
            candidate = self._find_candidate()
            if candidate is None:
                break

            parent, side, merge = candidate
            new_parent = parent.copy(statements=parent.statements[:-1])
            self._update_block(parent, new_parent)
            self._remove_block(side)

            if not self.out_graph.has_edge(new_parent, merge):
                self.out_graph.add_edge(new_parent, merge)

            changed = True
            _l.debug(
                "Removed redundant rejoin branch side block %#x from parent %#x to merge %#x.",
                side.addr,
                parent.addr,
                merge.addr,
            )

        if changed:
            self.out_graph = self._graph

    def _find_candidate(self):
        graph = self.out_graph if self.out_graph is not None else self._graph

        for parent in list(graph.nodes()):
            if not parent.statements or not isinstance(parent.statements[-1], ConditionalJump):
                continue

            succs = list(graph.successors(parent))
            if len(succs) != 2 or succs[0] == succs[1]:
                continue

            for side, merge in ((succs[0], succs[1]), (succs[1], succs[0])):
                if self._is_redundant_side(parent, side, merge, graph):
                    return parent, side, merge

        return None

    @staticmethod
    def _is_redundant_side(parent, side, merge, graph):
        if side == parent or merge == parent or side == merge:
            return False

        if not hasattr(side, "statements") or not hasattr(merge, "statements"):
            return False

        side_preds = list(graph.predecessors(side))
        if len(side_preds) != 1 or side_preds[0] != parent:
            return False

        side_succs = list(graph.successors(side))
        if len(side_succs) != 1 or side_succs[0] != merge:
            return False

        side_stmts = RedundantRejoinBranchRemover._side_effect_statements(side)
        if side_stmts is None:
            return False

        parent_stmts = [stmt for stmt in parent.statements[:-1] if not isinstance(stmt, Label)]

        return all(
            any(RedundantRejoinBranchRemover._same_statement(side_stmt, parent_stmt) for parent_stmt in parent_stmts)
            for side_stmt in side_stmts
        )

    @staticmethod
    def _side_effect_statements(block):
        stmts = []
        for stmt in block.statements:
            if isinstance(stmt, (Jump, Label)):
                continue
            if isinstance(stmt, (ConditionalJump, Call, DirtyStatement)):
                return None
            if not isinstance(stmt, (Assignment, Store)):
                return None
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, ailment.Expr.Tmp):
                return None
            stmts.append(stmt)
        return stmts

    @staticmethod
    def _same_statement(stmt_a, stmt_b):
        try:
            return stmt_a.likes(stmt_b)
        except AttributeError:
            return False

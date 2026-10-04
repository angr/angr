from __future__ import annotations

import logging
from collections import Counter

import networkx

from angr.ailment.expression import Call, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Label, SideEffectStatement, Statement
from angr.analyses.decompiler.known_patterns import (
    GateContext,
    KnownPatternFinder,
    PatternContext,
    partition_templates,
    patterns_for,
    resolve_pattern_selection,
)
from angr.analyses.decompiler.known_patterns.apply import apply_call_info_to_graph
from angr.analyses.decompiler.known_patterns.finder import _iter_stmt_subexprs
from angr.utils.ssa import is_phi_assignment

from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(__name__)


class KnownPatternOutliner(OptimizationPass):
    """
    Automatically finds occurrences of KnownPatterns (inlined library idioms
    such as std::string::length() or std::vector<int>::size(); see
    angr.analyses.decompiler.known_patterns) in the AIL graph and outlines them
    into calls via the KnownPatternFinder analysis.

    Runs right before variable recovery so that the synthesized calls' argument
    types flow into Typehoon within the same decompilation run.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Outline known code patterns into calls"
    DESCRIPTION = __doc__.strip() if __doc__ else ""

    MAX_ROUNDS = 8

    def __init__(self, func, manager, known_patterns=None, recognize_known_patterns=True, **kwargs):
        # the user's force-enable selection ("all", or names of opt-in templates); threaded down from the
        # ``known_patterns`` decompilation option through Clinic
        self._known_patterns = known_patterns
        # the on/off switch, from the ``recognize_known_patterns`` option. Off means the idioms decompile as the
        # arithmetic they are.
        self._recognize_known_patterns = recognize_known_patterns
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        if not self._recognize_known_patterns:
            return False, None

        ctx = PatternContext.from_project(self.project)
        templates = resolve_pattern_selection(self._known_patterns) if self._known_patterns is not None else None
        enabled, deferred = partition_templates(GateContext(ctx=ctx, project=self.project), templates=templates)
        return bool(patterns_for(ctx, enabled + deferred)), None

    def _analyze(self, cache=None):
        graph = self._graph
        block_addr_start = self.new_block_addr()
        changed = False
        pure_calls: set[str] = set()
        finder = None

        for _ in range(self.MAX_ROUNDS):
            finder = self.project.analyses[KnownPatternFinder].prep(kb=self.kb)(
                self._func,
                graph,
                vvar_id_start=max(self.vvar_id_start, 1),
                block_addr_start=block_addr_start,
                ail_manager=self.manager,
                patterns=resolve_pattern_selection(self._known_patterns) if self._known_patterns is not None else None,
            )
            if not finder.matches:
                break
            graph, applied = finder.apply_matches(finder.matches, graph)
            progressed = bool(applied)
            for m in finder.matches:
                if id(m) in applied:
                    pure_calls.update(m.pattern.pure_calls)
            changed = changed or progressed
            self.vvar_id_start = finder.vvar_id_start
            block_addr_start = finder.block_addr_start
            self._new_block_addrs.add(block_addr_start)
            if not progressed:
                break

        if changed:
            # peepholes have already run by this stage, so the prototypes of the
            # newly synthesized calls must be applied here for this run
            apply_call_info_to_graph(graph, self.manager, self.project)
            # A match that read through a definition (PDefOf) leaves that
            # definition behind: the ctype patterns hoist the table pointer out
            # of the loop and the table entry out of the predicates, and once
            # the predicates are named nothing reads either. The clinic's own
            # simplification rounds have all run by this stage, so the dead
            # assignments are ours to remove.
            graph = self._remove_dead_definitions(graph)
            self._fold_lifted_results(graph)
            if pure_calls and finder is not None:
                self._drop_pure_calls(graph, pure_calls, finder)
            self.out_graph = graph

    def _remove_dead_definitions(self, graph):
        """Dead-assignment removal and nothing more.

        Not :meth:`_simplify_graph`: that also folds expressions, and folding
        ``v = a0 + 32; f(v)`` into ``f(a0 + 32)`` costs Typehoon the field
        edge that made ``a0`` a struct. The calls we just synthesized carry the
        parameter types the folding would strip from their arguments.
        """
        for _ in range(self.MAX_ROUNDS):
            simp = self.project.analyses.AILSimplifier(
                self._func,
                func_graph=graph,
                ail_manager=self.manager,
                fold_expressions=False,
                use_callee_saved_regs_at_return=False,
                gp=self._func.info.get("gp", None) if self.project.arch.name in {"MIPS32", "MIPS64"} else None,
                avoid_vvar_ids=self._avoid_vvar_ids,
            )
            if not simp.simplified:
                break
            graph = simp.func_graph
        return graph

    @staticmethod
    def _fold_lifted_results(graph: networkx.DiGraph) -> None:
        """Fold ``tmp = known_call(...)`` into its single use when that use is the next statement
        (not a jump condition).

        The finder lifts a matched sub-expression into a TMP vvar so the
        Outliner can see a live-out; putting the call back where the
        expression was undoes only that, nothing the clinic folded.
        """
        uses: Counter[int] = Counter()
        for block in graph:
            for stmt in block.statements:
                for _, expr in _iter_stmt_subexprs(stmt, uses_only=True):
                    if isinstance(expr, VirtualVariable):
                        uses[expr.varid] += 1

        for block in list(graph):
            if not block.statements:
                continue
            stmt = block.statements[-1]
            if not (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.category == VirtualVariableCategory.TMP
                and isinstance(stmt.src, Call)
                and stmt.src.tags.get("known_pattern") is not None
                and stmt.src.bits >= 8
                and uses[stmt.dst.varid] == 1
            ):
                continue
            succs = list(graph.successors(block))
            if len(succs) != 1 or succs[0] is block or graph.in_degree(succs[0]) != 1:
                continue
            succ = succs[0]
            user_idx = next((i for i, s in enumerate(succ.statements) if not isinstance(s, Label)), None)
            if user_idx is None:
                continue
            user: Statement = succ.statements[user_idx]
            # a jump condition must stay a comparison for structuring
            if is_phi_assignment(user) or isinstance(user, ConditionalJump):
                continue
            use = next(
                (
                    e
                    for _, e in _iter_stmt_subexprs(user, uses_only=True)
                    if isinstance(e, VirtualVariable) and e.varid == stmt.dst.varid
                ),
                None,
            )
            if use is None:
                continue
            replaced, new_user = user.replace(use, stmt.src)
            if not replaced:
                continue
            succ.statements[user_idx] = new_user
            block.statements = block.statements[:-1]

    @staticmethod
    def _drop_pure_calls(graph, pure_calls: set[str], finder) -> None:
        """Remove bare calls to callees an applied pattern declared pure.

        By the time this runs the simplifier has turned every dead
        ``v = __ctype_b_loc()`` into ``__ctype_b_loc()``; a call with no result
        to a callee whose only effect *was* its result is nothing.
        """
        for block in graph.nodes:
            kept = [
                stmt
                for stmt in block.statements
                if not (
                    isinstance(stmt, SideEffectStatement)
                    and stmt.ret_expr is None
                    and stmt.fp_ret_expr is None
                    and isinstance(stmt.expr, Call)
                    and finder.call_target_names(stmt.expr) & pure_calls
                )
            ]
            if len(kept) != len(block.statements):
                block.statements = kept

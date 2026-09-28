from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.ailment.expression import Call, VirtualVariable
from angr.ailment.statement import Assignment, Return
from angr.analyses.decompiler.known_patterns.pattern import resolve_typeref
from angr.analyses.decompiler.utils import copy_graph
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.analyses.fuzzy_patterns.dedup import _restore, _snapshot, graph_problems, normalize_call_width
from angr.analyses.fuzzy_patterns.region import materialize, snap
from angr.analyses.fuzzy_patterns.search import search, tokenize_for_templates, verify
from angr.analyses.outliner import Outliner
from angr.sim_type import SimTypeFunction, parse_type

from .optimization_pass import OptimizationPass, OptimizationPassStage

if TYPE_CHECKING:
    import networkx

    from angr.ailment import Block
    from angr.analyses.fuzzy_patterns.search import TemplateMatch
    from angr.analyses.fuzzy_patterns.tokenizer import TokenStream
    from angr.knowledge_plugins.fuzzy_patterns import StoredPattern

_l = logging.getLogger(__name__)


class FuzzyPatternOutliner(OptimizationPass):
    """
    Finds occurrences of the user's fuzzy patterns (kb.fuzzy_patterns) in the AIL
    graph and outlines each into a call named after its pattern.

    Where the KnownPatternOutliner matches library idioms exactly, this pass aligns a
    pattern the user selected and edited, so an occurrence may differ from it in the
    ways the pattern allows: a different operator of the same class, a statement it
    marked optional, an extra statement in between. An occurrence is outlined when it
    verifies structurally and reaches the pattern's similarity threshold. Runs right
    before variable recovery so the calls' declared types flow into Typehoon.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Outline the user's fuzzy patterns into calls"
    DESCRIPTION = __doc__.strip() if __doc__ else ""

    MAX_ROUNDS = 32

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        #: (pattern name, block location of the call) for every occurrence outlined
        self.outlined: list[tuple[str, tuple[int, int | None]]] = []
        #: (pattern name, reason) for every occurrence that was found but not outlined
        self.skipped: list[tuple[str, str]] = []
        self.analyze()

    def _check(self):
        return bool(self.kb.fuzzy_patterns.enabled_patterns()), None

    def _analyze(self, cache=None):
        stored = self.kb.fuzzy_patterns.enabled_patterns()
        graph = copy_graph(self._graph)
        changed = False
        # an occurrence is identified by what it covers, so one that fails is not retried
        tried: set[tuple[str, tuple[int | None, int | None]]] = set()
        for _ in range(self.MAX_ROUNDS):
            entry = next((b for b in graph if b.addr == self._func.addr and b.idx is None), None)
            if entry is None:
                break
            stream = tokenize_for_templates(graph, entry, kb=self.kb)
            # a failed outline restores the graph, so the stream and the ranking stay good:
            # work down the list until one succeeds, and only then tokenize and search again
            outlined = False
            for pattern, match in self._ranked_hits(stream, stored, tried):
                tried.add((pattern.name, stream.addr_range(match.interval.start, match.interval.end)))
                if self._outline(graph, stream, pattern, match):
                    outlined = changed = True
                    break
            if not outlined:
                break
        if changed:
            self.out_graph = graph

    def _ranked_hits(
        self, stream: TokenStream, stored: list[StoredPattern], tried: set
    ) -> list[tuple[StoredPattern, TemplateMatch]]:
        """Every untried occurrence of any enabled pattern, most similar first, longest on ties."""
        hits: list[tuple[tuple[float, int], StoredPattern, TemplateMatch]] = []
        for entry in stored:
            for match in search(entry.pattern, stream):
                key = (entry.name, stream.addr_range(match.interval.start, match.interval.end))
                if key in tried or match.similarity < entry.min_similarity:
                    continue
                verify(match, entry.pattern, stream)
                if entry.require_verified and not match.verified:
                    continue
                hits.append(((match.similarity, len(match)), entry, match))
        hits.sort(key=lambda h: h[0], reverse=True)
        return [(entry, match) for _, entry, match in hits]

    def _outline(self, graph: networkx.DiGraph[Block], stream: TokenStream, stored: StoredPattern, match) -> bool:
        pattern = stored.pattern
        region = snap(stream, graph, match.interval, entry_loc=(self._func.addr, None))
        if not region.outlinable:
            self.skipped.append((pattern.name, region.reason))
            return False

        snapshot = _snapshot(graph)
        saved_vvar_id = self.vvar_id_start
        try:
            src_loc, frontier = materialize(
                graph, stream, region, self.new_block_addr, split_tail=True, idx_alloc=self.manager.next_atom
            )
            # taken after materialize, which allocates its split blocks the same way
            block_addr_start = self.new_block_addr()
            outliner = self.project.analyses[Outliner].prep(kb=self.kb)(
                self._func,
                graph,
                src_loc=src_loc,
                frontier=frontier,
                vvar_id_start=max(self.vvar_id_start, 1),
                block_addr_start=block_addr_start,
            )
        except Exception as ex:  # pylint:disable=broad-except
            _l.debug("outlining %s failed", pattern.name, exc_info=True)
            _restore(graph, snapshot)
            self.skipped.append((pattern.name, f"{type(ex).__name__}: {ex}"))
            return False
        self.vvar_id_start = outliner.vvar_id_start
        self._new_block_addrs.add(outliner.block_addr_start)

        reason = None
        if outliner.child_graph is None or len(outliner.child_graph) == 0:
            reason = "outliner produced an empty callee"
        else:
            normalize_call_width(graph, src_loc)
            problems = graph_problems(graph, self._func.addr)
            if problems:
                reason = f"would break SSA: {problems[0]}"
        if reason is not None:
            _restore(graph, snapshot)
            self.vvar_id_start = saved_vvar_id
            self.skipped.append((pattern.name, reason))
            return False

        outliner.child_func.name = pattern.call_name
        call = self._rename_call(graph, src_loc, pattern.call_name)
        if call is not None:
            self._declare_prototype(call, stored, match, outliner.child_graph)
        self.outlined.append((pattern.name, src_loc))
        return True

    @staticmethod
    def _rename_call(graph: networkx.DiGraph[Block], call_loc: tuple[int, int | None], name: str) -> Call | None:
        """Point the synthesized callsite at the pattern's call name; returns the new Call."""
        block = next((b for b in graph if (b.addr, b.idx) == call_loc), None)
        if block is None:
            return None
        for i, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                call = stmt.src
                new_call = Call(call.idx, name, args=call.args, bits=call.bits, **call.tags)
                block.statements[i] = Assignment(stmt.idx, stmt.dst, new_call, **stmt.tags)
                return new_call
        return None

    def _declare_prototype(self, call: Call, stored: StoredPattern, match, child_graph) -> None:
        """Give the callsite the types the pattern declares.

        The outliner orders arguments by liveness, not by the pattern's parameter
        list, so each argument is typed by the capture it binds. A callee that
        returns a value the pattern did not declare a type for is left alone: a
        wrong prototype is worse than none.
        """
        pattern = stored.pattern
        returns_value = any(
            isinstance(stmt, Return) and stmt.ret_exprs for block in child_graph for stmt in block.statements
        )
        if returns_value and pattern.returnty is None:
            return
        arch = self.project.arch
        by_varid = {}
        for param in pattern.params:
            bound = match.captures.get(param.capture)
            if isinstance(bound, VirtualVariable):
                by_varid[bound.varid] = param
        args = []
        for arg in call.args or ():
            param = by_varid.get(arg.varid) if isinstance(arg, VirtualVariable) else None
            ty = resolve_typeref(param.type, arch) if param is not None and param.type is not None else None
            args.append(ty if ty is not None else parse_type("void *").with_arch(arch))
        returnty = resolve_typeref(pattern.returnty, arch) if pattern.returnty is not None else None
        variable_map_of(self.manager).set_prototype(call, SimTypeFunction(args, returnty).with_arch(arch))

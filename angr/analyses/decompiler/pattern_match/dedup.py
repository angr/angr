"""``PatternDeduplicator``: outline discovered patterns and merge the sound ones.

Extraction happens in two steps.

*Outlining* lifts every selected region into its own function via
:class:`~angr.analyses.outliner.Outliner`. This always applies and is what
removes the duplicated bulk from the parent.

*Merging* then folds several outlined callees into a single shared function.
This is only sound when the callees are identical modulo constants, so each
group is re-verified at unlimited canonicalization depth (the shapes used for
discovery are depth-limited and would not prove it), the argument lists are put
into a canonical order, and the constants that actually differ are lifted into
extra parameters passed by each call site. Anything that fails a check is left
outlined but unmerged and reported, never merged approximately.

``granularity`` selects what gets outlined:

``"occurrence"``
    Each fuzzy occurrence becomes its own function. Maximum bulk removal from
    the parent; merging usually finds nothing, because near-duplicates that
    align at 90% are not identical.
``"core"``
    Only the exactly-shared cores are outlined. Every member of a core group is
    identical modulo constants by construction, so these always merge.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockRewriter, AILBlockViewer, AILBlockWalker
from angr.ailment.expression import Call, Const, Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Return, Statement
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.outliner import Outliner

from .align import Interval
from .region import materialize, snap
from .tokenizer import AILCanonicalizer, linearize

if TYPE_CHECKING:
    import networkx

    from angr.knowledge_plugins.functions import Function

    from .finder import FuzzyPattern
    from .tokenizer import TokenStream

_l = logging.getLogger(__name__)

Address = tuple[int, "int | None"]


@dataclass
class OutlinedRegion:
    """One region that was successfully lifted into its own function."""

    group_key: tuple
    interval: Interval
    src_loc: Address
    call_loc: Address
    child_func: Function
    child_graph: networkx.DiGraph[Block]
    child_args: list[VirtualVariable]
    consts: list[int] = field(default_factory=list)
    const_bits: list[int] = field(default_factory=list)
    #: indices into ``consts`` that are block addresses, meaningless across copies
    jump_target_consts: set[int] = field(default_factory=set)
    #: indices into ``consts`` that name a callee, which copies must agree on
    call_target_consts: set[int] = field(default_factory=set)
    shape: tuple[str, ...] = ()
    auto_frontier: bool = False

    @property
    def statements(self) -> int:
        """Statements actually moved into the callee.

        With a derived frontier this is not the interval length: the Outliner
        picks its own boundary, so the region it lifts can be smaller (or
        larger) than the interval that pointed at it.
        """
        return sum(len(b.statements) for b in self.child_graph)


@dataclass
class MergeGroup:
    """Several outlined regions folded into one shared function."""

    name: str
    members: list[OutlinedRegion]
    lifted_const_indices: list[int] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)


@dataclass
class DedupResult:
    """What :class:`PatternDeduplicator` did."""

    graph: networkx.DiGraph[Block]
    outlined: list[OutlinedRegion] = field(default_factory=list)
    groups: list[MergeGroup] = field(default_factory=list)
    skipped: list[tuple[Interval, str]] = field(default_factory=list)

    @property
    def statements_removed(self) -> int:
        """Statements actually moved out of the parent."""
        return sum(r.statements for r in self.outlined)


class _ConstRole:
    """Tells a jump target and a call target apart from a value while a walker descends.

    Identity is no use here: a Rust-backed AIL object hands out a fresh Python
    wrapper on every attribute access. The walk path is: a constant directly under
    a Jump, or in target position directly under a ConditionalJump, is a block
    address; one the Call handler walks at index -1 is the callee.
    """

    def __init__(self):
        self._depth = 0

    def _enter(self) -> None:
        self._depth += 1

    def _leave(self) -> None:
        self._depth -= 1

    def _role(self, expr_idx: int, stmt: Statement | None) -> str | None:
        # a statement's own -1 slot is a side-effect statement's return expression
        if expr_idx == -1 and self._depth >= 2:
            return "call"
        if self._depth == 1 and isinstance(stmt, Jump):
            return "jump"
        if self._depth == 1 and isinstance(stmt, ConditionalJump) and expr_idx in (1, 2):
            return "jump"
        return None


class _ConstCollector(AILBlockViewer, _ConstRole):
    """Collects Const values and widths in deterministic walk order.

    A jump target is a block address, not a value: two copies of an idiom differ
    in theirs without meaning anything by it, so those indices are reported in
    ``jump_targets`` and ignored when bodies are compared. A call target is what
    the body does, so it is reported in ``call_targets`` and must agree.
    """

    def __init__(self):
        AILBlockViewer.__init__(self)
        _ConstRole.__init__(self)
        self.values: list[int] = []
        self.widths: list[int] = []
        self.jump_targets: set[int] = set()
        self.call_targets: set[int] = set()

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        self._enter()
        try:
            return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        finally:
            self._leave()

    def _handle_Const(self, expr_idx, expr, stmt_idx, stmt, block):
        idx = len(self.values)
        role = self._role(expr_idx, stmt)
        if role == "jump":
            self.jump_targets.add(idx)
        elif role == "call":
            self.call_targets.add(idx)
        self.values.append(expr.value)
        self.widths.append(expr.bits)


class _ConstLifter(AILBlockRewriter, _ConstRole):
    """Replaces selected Consts (by walk-order index) with parameter vvars. The
    indices are counted the way :class:`_ConstCollector` counts them; a jump or
    call target is never replaced, whatever the request says."""

    def __init__(self, replacements: dict[int, VirtualVariable]):
        AILBlockRewriter.__init__(self, update_block=False)
        _ConstRole.__init__(self)
        self._replacements = replacements
        self.counter = 0
        self.replaced = 0

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        # one pass, not the rewriter's re-walk to a fixed point: a re-walked call
        # would count its target twice and the indices would drift from the collector's
        self._enter()
        try:
            return AILBlockWalker._dispatch_expr(self, expr_idx, expr, stmt_idx, stmt, block)
        finally:
            self._leave()

    def _handle_Const(self, expr_idx, expr, stmt_idx, stmt, block):
        idx = self.counter
        self.counter += 1
        repl = self._replacements.get(idx)
        if repl is None or self._role(expr_idx, stmt) is not None:
            return expr
        self.replaced += 1
        return repl.copy()


class _VVarUseCollector(AILBlockViewer):
    """Collects vvar ids in deterministic walk order."""

    def __init__(self):
        super().__init__()
        self.order: list[int] = []
        self._seen: set[int] = set()

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.varid not in self._seen:
            self._seen.add(expr.varid)
            self.order.append(expr.varid)


def graph_problems(graph: networkx.DiGraph[Block], func_addr: int | None = None) -> list[str]:
    """Structural invariants the decompiler relies on, checked after an outline.

    Three things go wrong in practice, and all three surface far downstream as
    an unrelated crash, so they are caught here instead:

    * A phi keeps sourcing a block that is gone. The Outliner keeps the source
      block's phis in the caller, moves every block the region reaches into the
      callee, and rewrites frontier phis to the call or dispatcher block;
      ``materialize`` splits a head's phis off so a loop back to it exits the
      region. What is left is a frontier phi reached through several new
      predecessors at once, which ``_update_phi_stmts`` leaves alone.
    * Two blocks end up sharing ``(addr, idx)``. ``GraphDephicationVVarMapping``
      keys blocks by that pair in a plain dict, so one silently shadows the
      other and statement-index lookups land in the wrong block.
    * A vvar gains a second definition. Definition locations are keyed by varid
      in a plain dict too, so the second write wins and the recorded index then
      points at an unrelated statement.

    Outlines that introduce any of these are rolled back rather than handed on.
    """
    problems: list[str] = []

    seen: dict[Address, Block] = {}
    for block in graph:
        loc = (block.addr, block.idx)
        if loc in seen:
            problems.append(f"duplicate block location {loc[0]:#x}.{loc[1]}")
        seen[loc] = block

    if func_addr is not None:
        entries = [b for b in graph if b.addr == func_addr and b.idx is None]
        if len(entries) != 1:
            problems.append(f"expected exactly one entry block at {func_addr:#x}, found {len(entries)}")

    defs: dict[int, list[str]] = {}
    for block in graph:
        preds = {(p.addr, p.idx) for p in graph.predecessors(block)}
        for i, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                defs.setdefault(stmt.dst.varid, []).append(f"{block.addr:#x}.{block.idx}[{i}]")
            if not isinstance(stmt, Assignment) or not isinstance(stmt.src, Phi):
                continue
            for src, _ in stmt.src.src_and_vvars:
                if src not in seen:
                    problems.append(f"phi at {block.addr:#x}.{block.idx}[{i}] sources removed block {src}")
                elif src not in preds:
                    problems.append(f"phi at {block.addr:#x}.{block.idx}[{i}] sources non-predecessor {src}")

    # SSA: one definition per vvar. Dephication keys definition locations by
    # varid in a plain dict, so a second definition overwrites the first and
    # later statement-index lookups land on an unrelated statement.
    for varid, locs in defs.items():
        if len(locs) > 1:
            problems.append(f"vvar {varid} is defined {len(locs)} times: {', '.join(locs[:4])}")
    return problems


def normalize_call_width(graph: networkx.DiGraph[Block], call_loc: Address) -> bool:
    """Rebuild a synthesized call at the width of the variable it is assigned to.

    The Outliner mints the callsite at return-register width, then overwrites
    the destination with the region's live-out variable, which is often
    narrower. Variable recovery later evaluates the assignment and dies on the
    width mismatch ("args' length must all be equal"), so fix it at the source.
    """
    block = next((b for b in graph if (b.addr, b.idx) == call_loc), None)
    if block is None:
        return False
    for i, stmt in enumerate(block.statements):
        if not isinstance(stmt, Assignment) or not isinstance(stmt.src, Call):
            continue
        if stmt.dst.bits == stmt.src.bits:
            return True
        call = stmt.src
        block.statements[i] = Assignment(
            stmt.idx,
            stmt.dst,
            Call(call.idx, call.target, args=call.args, bits=stmt.dst.bits, **call.tags),
            **stmt.tags,
        )
        return True
    return False


def _snapshot_stmt(stmt):
    """Rebuild phi assignments so a rollback cannot leave an edited phi behind.

    ``Outliner._update_phi_stmts`` replaces the statement rather than editing
    the phi, so restoring the statement list is enough today. Copying anyway
    keeps the undo correct if any rewriter ever edits a phi's sources in place.
    """
    if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
        phi = stmt.src
        return Assignment(stmt.idx, stmt.dst, Phi(phi.idx, phi.bits, list(phi.src_and_vvars), **phi.tags), **stmt.tags)
    return stmt


def _snapshot(graph: networkx.DiGraph[Block]) -> tuple[list[Block], list[tuple[Block, Block, dict]], list[list]]:
    """Undo record: node set, edge set, and each block's statement list."""
    return (
        list(graph.nodes),
        [(u, v, dict(d)) for u, v, d in graph.edges(data=True)],
        [[_snapshot_stmt(s) for s in b.statements] for b in graph.nodes],
    )


def _restore(graph: networkx.DiGraph[Block], snapshot) -> None:
    nodes, edges, statements = snapshot
    graph.clear()
    graph.add_nodes_from(nodes)
    graph.add_edges_from(edges)
    for block, stmts in zip(nodes, statements):
        block.statements = stmts


def _entry_block(graph: networkx.DiGraph[Block]) -> Block | None:
    roots = [b for b in graph if graph.in_degree[b] == 0]
    if roots:
        return min(roots, key=lambda b: (b.addr, -1 if b.idx is None else b.idx))
    return min(graph, key=lambda b: (b.addr, -1 if b.idx is None else b.idx)) if len(graph) else None


def _canonical_blocks(graph: networkx.DiGraph[Block]) -> list[Block]:
    entry = _entry_block(graph)
    return linearize(graph, entry) if entry is not None else []


def callee_shape(graph: networkx.DiGraph[Block]) -> tuple[str, ...]:
    """Full-depth canonical shape of a callee body, for merge verification.

    Discovery uses depth-limited shapes, which cannot prove two bodies equal:
    anything below the depth cut renders as ``?``. Merging re-derives the shape
    with no depth limit so equality really means identical modulo constants.
    """
    canon = AILCanonicalizer(max_depth=1 << 30, keep_vvar_category=True, const_mode="abstract")
    out: list[str] = []
    for pos, block in enumerate(_canonical_blocks(graph)):
        for stmt in block.statements:
            out.append(canon.statement(stmt, pos))
    return tuple(out)


def callee_consts(graph: networkx.DiGraph[Block]) -> tuple[list[int], list[int], set[int], set[int]]:
    """Const values and widths of a callee body, ordered as in :func:`callee_shape`,
    with the indices that are jump targets and those that are call targets."""
    collector = _ConstCollector()
    for block in _canonical_blocks(graph):
        collector.walk(block)
    return collector.values, collector.widths, collector.jump_targets, collector.call_targets


def canonical_arg_order(graph: networkx.DiGraph[Block], args: list[VirtualVariable]) -> list[VirtualVariable]:
    """Order ``args`` by first use in the callee body.

    The Outliner derives its interface from a dict of definitions, so two
    structurally identical callees can end up with their parameters in
    different orders. Sorting by first use makes the k-th parameter mean the
    same thing in every member of a merge group.
    """
    collector = _VVarUseCollector()
    for block in _canonical_blocks(graph):
        collector.walk(block)
    rank = {varid: i for i, varid in enumerate(collector.order)}
    return sorted(args, key=lambda v: (rank.get(v.varid, len(rank)), v.varid))


class PatternDeduplicator(Analysis):
    """Outline fuzzy patterns out of a function and merge the provably equal ones.

    :param func:            The function being rewritten.
    :param ail_graph:       Its AIL graph. Not mutated; a copy is rewritten.
    :param patterns:        Patterns from :class:`.FuzzyPatternFinder`.
    :param granularity:     ``"core"`` (default, always mergeable) or
                            ``"occurrence"`` (maximum bulk removal).
    :param merge:           Fold provably identical callees into one function.
    :param frontier_mode:   ``"region"`` outlines exactly the discovered
                            interval; ``"fallback"`` (default) additionally
                            retries regions that are not single-entry by
                            letting the Outliner derive its own frontier.
    :param max_auto_blocks: Bound, as a multiple of the region's block count,
                            on how large a derived frontier may grow.
    :param min_auto_ratio:  Smallest fraction of the region a derived frontier
                            may cover before the outline is judged unrelated
                            to the pattern and rolled back.
    :param name_prefix:     Prefix for synthesized function names.
    """

    def __init__(
        self,
        func: Function,
        ail_graph: networkx.DiGraph[Block],
        patterns: list[FuzzyPattern],
        stream: TokenStream,
        *,
        granularity: str = "core",
        merge: bool = True,
        name_prefix: str = "fuzzy",
        vvar_id_start: int = 0xD000,
        block_addr_start: int = 0xABCD_0000,
        const_param_stack_base: int = -0x10000,
        min_group_size: int = 2,
        validate: bool = True,
        frontier_mode: str = "fallback",
        max_auto_blocks: int = 3,
        min_auto_ratio: float = 0.5,
    ):
        if granularity not in ("core", "occurrence"):
            raise ValueError(f"unknown granularity {granularity!r}")
        if frontier_mode not in ("region", "fallback"):
            raise ValueError(f"unknown frontier_mode {frontier_mode!r}")
        from angr.analyses.decompiler.clinic import Clinic

        self.func = func
        self.stream = stream
        self.granularity = granularity
        self.name_prefix = name_prefix
        self.min_group_size = min_group_size
        self.vvar_id_start = vvar_id_start
        self.block_addr_start = block_addr_start
        self.const_param_stack_base = const_param_stack_base
        self.validate = validate
        self.frontier_mode = frontier_mode
        self.max_auto_blocks = max_auto_blocks
        self.min_auto_ratio = min_auto_ratio

        graph = Clinic._copy_graph(ail_graph)
        self.result = DedupResult(graph=graph)
        self._outline_all(graph, patterns)
        if merge:
            self._merge(graph)

    def _next_block_addr(self) -> int:
        addr = self.block_addr_start
        self.block_addr_start += 1
        return addr

    #
    # outlining
    #

    def _targets(self, patterns: list[FuzzyPattern]) -> list[tuple[tuple, Interval]]:
        targets: list[tuple[tuple, Interval]] = []
        for pi, pattern in enumerate(patterns):
            if self.granularity == "occurrence":
                for occ in pattern.occurrences:
                    targets.append(((pi,), occ.interval))
            else:
                for ci, core in enumerate(pattern.cores):
                    if core.support < self.min_group_size:
                        continue
                    for iv in core.occurrences:
                        targets.append(((pi, ci), iv))

        # largest first: each outline rewrites the graph, so overlapping regions are
        # settled in favor of the one that saves more, but only once it has succeeded
        targets.sort(key=lambda t: (-len(t[1]), t[1].start))
        return targets

    def _outline_all(self, graph: networkx.DiGraph[Block], patterns: list[FuzzyPattern]) -> None:
        entry = _entry_block(graph)
        entry_loc = (entry.addr, entry.idx) if entry is not None else None

        taken: list[Interval] = []
        for key, interval in self._targets(patterns):
            if any(interval.overlaps(other) for other in taken):
                # a larger region that was outlined owns these tokens; one that failed
                # released them, so a smaller pattern underneath still gets its turn
                continue
            region = snap(self.stream, graph, interval, entry_loc=entry_loc)

            # A contiguous token range is not automatically a single-entry
            # region: reverse post-order interleaves blocks from different
            # parts of the CFG, so one logical chunk of duplicated code can
            # still be jumped into from elsewhere. When that is the only
            # objection, hand the Outliner just the start location and let it
            # derive the frontier from dominance and liveness, the way a
            # hand-written outlining call does. Correctness still rests on the
            # post-outline validation below.
            auto = False
            if not region.outlinable:
                if self.frontier_mode == "region" or "entered from outside" not in region.reason:
                    self.result.skipped.append((interval, region.reason))
                    continue
                auto = True

            snapshot = _snapshot(graph) if self.validate else None
            saved_ids = (self.vvar_id_start, self.block_addr_start)
            try:
                src_loc, frontier = materialize(graph, self.stream, region, self._next_block_addr, split_tail=not auto)
                outliner = self.project.analyses[Outliner].prep(kb=self.kb)(
                    self.func,
                    graph,
                    src_loc=src_loc,
                    frontier=None if auto else frontier,
                    min_step=2 if auto else 1,
                    vvar_id_start=self.vvar_id_start,
                    block_addr_start=self.block_addr_start,
                )
            except Exception as ex:  # pylint:disable=broad-except
                _l.debug("outlining [%d,%d) failed", interval.start, interval.end, exc_info=True)
                if snapshot is not None:
                    _restore(graph, snapshot)
                self.vvar_id_start, self.block_addr_start = saved_ids
                self.result.skipped.append((interval, f"{type(ex).__name__}: {ex}"))
                continue

            self.vvar_id_start = outliner.vvar_id_start
            self.block_addr_start = outliner.block_addr_start
            child_graph = outliner.child_graph
            reject = None
            if child_graph is None or len(child_graph) == 0:
                reject = "outliner produced an empty callee"
            elif auto and len(child_graph) > self.max_auto_blocks * max(1, len(region.block_locs)):
                # a derived frontier can swallow the rest of the function
                reject = (
                    f"auto frontier ran away: {len(child_graph)} blocks for a {len(region.block_locs)}-block region"
                )
            elif auto and len(child_graph) < self.min_auto_ratio * len(region.block_locs):
                # ...or stop so early that it does not extract the pattern at all
                reject = (
                    f"auto frontier too small: {len(child_graph)} blocks for a {len(region.block_locs)}-block region"
                )
            if reject is not None:
                if snapshot is not None:
                    _restore(graph, snapshot)
                self.vvar_id_start, self.block_addr_start = saved_ids
                self.result.skipped.append((interval, reject))
                continue

            normalize_call_width(graph, src_loc)

            if snapshot is not None:
                problems = graph_problems(graph, self.func.addr)
                if problems:
                    _restore(graph, snapshot)
                    self.vvar_id_start, self.block_addr_start = saved_ids
                    self.result.skipped.append((interval, f"would break SSA: {problems[0]}"))
                    continue

            taken.append(interval)
            values, widths, jump_targets, call_targets = callee_consts(child_graph)
            self.result.outlined.append(
                OutlinedRegion(
                    group_key=key,
                    interval=interval,
                    src_loc=src_loc,
                    call_loc=src_loc,
                    child_func=outliner.child_func,
                    child_graph=child_graph,
                    child_args=canonical_arg_order(child_graph, list(outliner.child_funcargs)),
                    consts=values,
                    const_bits=widths,
                    jump_target_consts=jump_targets,
                    call_target_consts=call_targets,
                    shape=callee_shape(child_graph),
                    auto_frontier=auto,
                )
            )

    #
    # merging
    #

    def _merge(self, graph: networkx.DiGraph[Block]) -> None:
        by_shape: dict[tuple, list[OutlinedRegion]] = {}
        for region in self.result.outlined:
            by_shape.setdefault((region.shape, len(region.child_args)), []).append(region)

        for idx, (_, members) in enumerate(sorted(by_shape.items(), key=lambda kv: -len(kv[1]))):
            if len(members) < self.min_group_size:
                continue
            if len({len(m.consts) for m in members}) != 1:
                # identical shapes must imply identical const counts; bail loudly if not
                _l.warning("fuzzy dedup: shape-equal callees disagree on constant count; not merging")
                continue

            differing = [i for i in range(len(members[0].consts)) if len({m.consts[i] for m in members}) > 1]
            if any(i in members[0].call_target_consts for i in differing):
                # same shape, different callees: not one function
                continue
            lifted = [i for i in differing if i not in members[0].jump_target_consts]
            name = f"{self.name_prefix}_{idx}"
            if not self._apply_merge(graph, members, lifted, name):
                continue
            self.result.groups.append(MergeGroup(name=name, members=members, lifted_const_indices=lifted))

    def _apply_merge(
        self,
        graph: networkx.DiGraph[Block],
        members: list[OutlinedRegion],
        lifted: list[int],
        name: str,
    ) -> bool:
        rep = members[0]
        # everything below edits the representative and the callsites in place; a
        # member whose callsite cannot be rewritten must leave no trace of the attempt
        undo = (
            _snapshot(rep.child_graph),
            _snapshot(graph),
            list(rep.child_args),
            rep.child_func.name,
            self.const_param_stack_base,
        )

        def rollback() -> bool:
            _restore(rep.child_graph, undo[0])
            _restore(graph, undo[1])
            rep.child_args = undo[2]
            rep.child_func.name = undo[3]
            self.const_param_stack_base = undo[4]
            return False

        extra_params: list[VirtualVariable] = []
        replacements: dict[int, VirtualVariable] = {}
        # lifted constants have no calling-convention home, so give them
        # synthetic stack slots below the frame: extra arguments go on the stack
        stack_offset = self.const_param_stack_base
        for const_idx in lifted:
            width = max((_const_bits(m, const_idx) for m in members), default=64)
            vvar = VirtualVariable(
                None,
                self._next_vvar_id(),
                width,
                VirtualVariableCategory.PARAMETER,
                (VirtualVariableCategory.STACK, stack_offset),
            )
            stack_offset -= 8
            extra_params.append(vvar)
            replacements[const_idx] = vvar
        self.const_param_stack_base = stack_offset

        if replacements:
            lifter = _ConstLifter(replacements)
            for block in _canonical_blocks(rep.child_graph):
                new_block = lifter.walk(block)
                if new_block is not block:
                    block.statements = new_block.statements
            if lifter.replaced != len(replacements):
                _l.warning(
                    "fuzzy dedup: expected to lift %d constants but lifted %d; not merging %s",
                    len(replacements),
                    lifter.replaced,
                    name,
                )
                return rollback()

        rep.child_args = rep.child_args + extra_params
        rep.child_func.name = name

        for member in members:
            extra_args = [Const(None, member.consts[i], _const_bits(member, i)) for i in lifted]
            if not self._rewrite_call(graph, member, name, extra_args):
                return rollback()
        return True

    def _rewrite_call(
        self,
        graph: networkx.DiGraph[Block],
        member: OutlinedRegion,
        name: str,
        extra_args: list[Const],
    ) -> bool:
        block = next((b for b in graph if (b.addr, b.idx) == member.call_loc), None)
        if block is None:
            _l.warning("fuzzy dedup: call block %s vanished", member.call_loc)
            return False
        for i, stmt in enumerate(block.statements):
            # a closed region's callsite returns the call rather than assigning it
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                call = stmt.src
            elif isinstance(stmt, Return) and len(stmt.ret_exprs or ()) == 1 and isinstance(stmt.ret_exprs[0], Call):
                call = stmt.ret_exprs[0]
            else:
                continue
            args = list(call.args or [])
            order = {v.varid: k for k, v in enumerate(member.child_args)}
            args.sort(key=lambda a: order.get(getattr(a, "varid", -1), len(order)))
            new_call = Call(
                call.idx,
                name,
                args=args + list(extra_args),
                bits=call.bits,
                **call.tags,
            )
            if isinstance(stmt, Assignment):
                block.statements[i] = Assignment(stmt.idx, stmt.dst, new_call, **stmt.tags)
            else:
                block.statements[i] = Return(stmt.idx, [new_call], **stmt.tags)
            return True
        _l.warning("fuzzy dedup: no call statement at %s", member.call_loc)
        return False

    def _next_vvar_id(self) -> int:
        vvar_id = self.vvar_id_start
        self.vvar_id_start += 1
        return vvar_id

    #
    # reporting
    #

    def summary(self) -> str:
        r = self.result
        lines = [
            (
                f"PatternDeduplicator({self.granularity}): {len(r.outlined)} regions outlined, "
                f"{len(r.groups)} merge groups, {len(r.skipped)} skipped, "
                f"{r.statements_removed} statements moved out of the parent"
            )
        ]
        for g in r.groups:
            lines.append(
                f"  {g.name}: {g.size} call sites share one function, {len(g.lifted_const_indices)} constants lifted"
            )
        for interval, reason in r.skipped[:20]:
            lines.append(f"  skipped [{interval.start},{interval.end}): {reason}")
        return "\n".join(lines)


def _const_bits(region: OutlinedRegion, const_idx: int) -> int:
    """Width of the ``const_idx``-th constant in a callee, defaulting to the pointer width."""
    return region.const_bits[const_idx] if const_idx < len(region.const_bits) else 64


AnalysesHub.register_default("PatternDeduplicator", PatternDeduplicator)

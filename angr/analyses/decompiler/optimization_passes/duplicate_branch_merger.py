"""Merge an if/else whose two branches compute the same thing.

Obfuscators emit opaque predicates whose two arms are semantically identical, e.g.::

    if (__CFADD__(x, 239) & 1) { a = b; c = d; } else { a = b; c = d; }

On one VMProtect-protected driver, 202 of the 214 if/else constructs across 15 decompiled
functions had this shape -- 201 of them exactly two statements long.

After SSA the two arms are *not* literally identical: each assigns to its own virtual
variable and a phi at the join selects between them::

    TRUE :  vvar_391  = Conv(64->8, vvar_4877)      FALSE:  vvar_387  = Conv(64->8, vvar_4877)
            vvar_4903 = vvar_4851                           vvar_4902 = vvar_4851
    join :  vvar_4798 = Phi([(true, vvar_4903), (false, vvar_4902)])
            vvar_130  = Phi([(true, vvar_391),  (false, vvar_387)])

so an exact ``likes()`` comparison never matches, which is why the older
``remove_same_branches`` never fired once SSA was in place. The comparison here is modulo
destination renaming, and the merge repairs the phis it invalidates.

An incorrect merge silently changes behaviour, so every check is conservative and anything
unrecognised bails out.
"""

from __future__ import annotations

import logging

from angr import ailment
from angr.ailment.block_walker import AILBlockRewriter, AILBlockViewer

from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)

#: Default cap on how many statements a duplicated arm may hold.
DEFAULT_MAX_DUPLICATED_BRANCH_STMTS = 4

#: Flag helpers the ccall rewriters emit as named calls. They are pure functions of their
#: arguments, so dropping one loses nothing -- unlike a real call.
_PURE_HELPER_CALLS = frozenset({"__CFADD__", "__OFADD__", "__OFSUB__", "__OFUMUL__", "__OFSMUL__"})


class _SideEffectChecker(AILBlockViewer):
    """Flags expressions that must not be duplicated or dropped.

    Calls and dirty helpers are rejected: they can do anything. Loads are *not* -- both arms are
    entered directly from the same branch block, so they see the same memory, and the merge keeps
    one arm rather than deleting both, so an identical load still happens exactly once on the
    path. VEX ccalls are likewise kept: they are pure functions of their arguments (flag
    computations), and anything impure nested inside one is still caught while recursing.
    """

    def __init__(self):
        super().__init__()
        self.unsafe = False
        self.expr_handlers[ailment.expression.DirtyExpression] = self._mark
        self.expr_handlers[ailment.expression.Call] = self._handle_call

    def _mark(self, *args, **kwargs):  # pylint:disable=unused-argument
        self.unsafe = True

    def _handle_call(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        if isinstance(expr.target, str) and expr.target in _PURE_HELPER_CALLS:
            for idx, arg in enumerate(expr.args or []):
                self._handle_expr(idx, arg, stmt_idx, stmt, block)
            return
        self.unsafe = True


def _expr_is_pure(expr) -> bool:
    """True if `expr` can be evaluated on the merged path without changing behaviour."""
    checker = _SideEffectChecker()
    try:
        checker.walk_expression(expr)
    except Exception:  # pylint:disable=broad-except
        return False
    return not checker.unsafe


def _rename_vvars(expr, mapping: dict[int, int]):
    """Return `expr` with every virtual variable in `mapping` replaced by its counterpart.

    Returns None if the rewrite fails, which the caller treats as "do not merge".
    """
    if not mapping:
        return expr

    if set(mapping) & set(mapping.values()):
        return None  # renaming would chain; refuse rather than iterate to a fixed point

    def _replace(expr_idx, vvar, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        # AILBlockRewriter handlers must return an expression, never None.
        target = mapping.get(vvar.varid)
        if target is None:
            return vvar
        return ailment.expression.VirtualVariable(
            vvar.idx, target, vvar.bits, vvar.category, oident=vvar.oident, **vvar.tags
        )

    rewriter = AILBlockRewriter(update_block=False)
    rewriter.expr_handlers[ailment.expression.VirtualVariable] = _replace
    try:
        rewritten = rewriter.walk_expression(expr)
    except Exception:  # pylint:disable=broad-except
        return None
    return expr if rewritten is None else rewritten


def _real_statements(block):
    """The block's statements minus labels and the trailing goto/jump."""
    out = []
    for stmt in block.statements:
        if isinstance(stmt, ailment.statement.Label):
            continue
        if isinstance(stmt, (ailment.statement.Jump, ailment.statement.ConditionalJump)):
            continue
        out.append(stmt)
    return out


def _equivalent_modulo_renaming(kept_stmts, dropped_stmts, seed=None):
    """Pair up two arms' statements, allowing their destination vvars to differ.

    Returns ``{dropped_varid: kept_varid}`` when the arms compute the same thing, else None.
    Only assignments are accepted and every source must be pure. Sources are compared after the
    mapping built so far is applied to the dropped side, so an arm may use vvars it defined
    itself; the mapping must stay consistent across the whole arm.
    """
    if len(kept_stmts) != len(dropped_stmts):
        return None

    mapping: dict[int, int] = dict(seed or {})
    for kept, dropped in zip(kept_stmts, dropped_stmts):
        # AIL statements are Rust-backed: every variant shares one Python type, so each side
        # has to be tested on its own rather than compared with type().
        if not isinstance(kept, ailment.statement.Assignment) or not isinstance(
            dropped, ailment.statement.Assignment
        ):
            return None
        if not _expr_is_pure(kept.src) or not _expr_is_pure(dropped.src):
            return None
        renamed_src = _rename_vvars(dropped.src, mapping)
        if renamed_src is None or not kept.src.likes(renamed_src):
            return None
        kept_dst, dropped_dst = kept.dst, dropped.dst
        if isinstance(kept_dst, ailment.expression.VirtualVariable) and isinstance(
            dropped_dst, ailment.expression.VirtualVariable
        ):
            if kept_dst.bits != dropped_dst.bits or kept_dst.category != dropped_dst.category:
                return None
            previous = mapping.get(dropped_dst.varid)
            if previous is not None and previous != kept_dst.varid:
                return None
            mapping[dropped_dst.varid] = kept_dst.varid
        elif not kept_dst.likes(dropped_dst):
            return None
    return mapping


class _VVarReaders(AILBlockViewer):
    """Where each virtual variable is read: ``varid -> {(block, in_a_phi)}``.

    Built once per graph. A merge only ever deletes blocks and shortens phis, so an entry can
    become stale only by naming a reader that no longer exists -- which makes the check stricter,
    never looser.
    """

    def __init__(self, graph):
        super().__init__()
        self.expr_handlers[ailment.expression.VirtualVariable] = self._record
        self.readers: dict[int, set[tuple[int, bool]]] = {}
        self._block = None
        self._in_phi = False
        for block in graph.nodes():
            self._block = block
            for idx, stmt in enumerate(block.statements):
                self._in_phi = isinstance(stmt, ailment.statement.Assignment) and isinstance(
                    stmt.src, ailment.expression.Phi
                )
                self.walk_statement(stmt, block, idx)

    def _record(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        self.readers.setdefault(expr.varid, set()).add((id(self._block), self._in_phi))

    def note_read(self, varid: int, block, in_phi: bool) -> None:
        """Register a read introduced while rewriting a phi."""
        self.readers.setdefault(varid, set()).add((id(block), in_phi))

    def only_read_by(self, varids, dropped_block, join_block) -> bool:
        """True if every read of `varids` is inside `dropped_block` or in a phi at the join."""
        dropped_id, join_id = id(dropped_block), id(join_block)
        for varid in varids:
            for block_id, in_phi in self.readers.get(varid, ()):
                if block_id == dropped_id:
                    continue
                if block_id == join_id and in_phi:
                    continue
                return False
        return True


def _repair_phis(join_block, kept_block, dropped_block, mapping: dict[int, int], readers):
    """Rebuild the join's phis without `dropped_block`, or return None if that is unsound.

    A phi at the join is what makes the two arms observable apart. Dropping an arm is only
    correct when every phi would have selected the same value either way: the entry coming from
    the dropped arm must be the entry coming from the kept arm, up to the arm's own renaming. A
    phi that selects genuinely different values -- ``x = cond ? a : b`` -- must not be collapsed,
    and neither must one that has an entry for the dropped arm but none for the kept arm, since
    the surviving path would be left without a value.
    """
    new_stmts = []
    changed = False
    for stmt in join_block.statements:
        if isinstance(stmt, ailment.statement.Assignment) and isinstance(stmt.src, ailment.expression.Phi):
            entries = list(stmt.src.src_and_vvars)
            dropped_entries = [(src, vvar) for src, vvar in entries if _is_from(src, dropped_block)]
            if dropped_entries:
                kept_entries = [(src, vvar) for src, vvar in entries if _is_from(src, kept_block)]
                if len(dropped_entries) != 1 or len(kept_entries) != 1:
                    return None
                dropped_vvar, kept_vvar = dropped_entries[0][1], kept_entries[0][1]
                if dropped_vvar is None or kept_vvar is None:
                    if dropped_vvar is not kept_vvar:
                        return None
                elif mapping.get(dropped_vvar.varid, dropped_vvar.varid) != kept_vvar.varid:
                    return None

                changed = True
                remaining = [(src, vvar) for src, vvar in entries if not _is_from(src, dropped_block)]
                if len(remaining) == 1 and remaining[0][1] is not None:
                    # one incoming value left: a plain copy says the same thing, and the read it
                    # leaves behind is no longer a phi read
                    readers.note_read(remaining[0][1].varid, join_block, False)
                    new_stmts.append(
                        ailment.statement.Assignment(stmt.idx, stmt.dst, remaining[0][1], **stmt.tags)
                    )
                    continue
                for _, vvar in remaining:
                    if vvar is not None:
                        readers.note_read(vvar.varid, join_block, True)
                new_phi = ailment.expression.Phi(stmt.src.idx, stmt.src.bits, remaining, **stmt.src.tags)
                new_stmts.append(ailment.statement.Assignment(stmt.idx, stmt.dst, new_phi, **stmt.tags))
                continue
        new_stmts.append(stmt)
    return new_stmts if changed else join_block.statements


def _both_targets_are(cond_jump, block) -> bool:
    """True if both of a conditional jump's targets name `block`."""

    def _names(target, target_idx):
        return (
            isinstance(target, ailment.expression.Const)
            and target.value == block.addr
            and (target_idx or None) == (block.idx or None)
        )

    return _names(cond_jump.true_target, cond_jump.true_target_idx) and _names(
        cond_jump.false_target, cond_jump.false_target_idx
    )


def _jump_to(block, replaced_stmt, manager):
    """An unconditional jump to `block`, taking the replaced statement's idx and tags."""
    target = ailment.expression.Const(
        manager.next_atom() if manager is not None else None, block.addr, replaced_stmt.true_target.bits
    )
    return ailment.statement.Jump(replaced_stmt.idx, target, target_idx=block.idx, **replaced_stmt.tags)


def _is_from(src, block) -> bool:
    """True if a phi source key names `block`."""
    return src[0] == block.addr and (src[1] or None) == (block.idx or None)


def _is_phi(stmt) -> bool:
    return isinstance(stmt, ailment.statement.Assignment) and isinstance(stmt.src, ailment.expression.Phi)


def _phi_entry(phi, block):
    """The value a phi takes when entered from `block`: (found, vvar)."""
    hits = [vvar for src, vvar in phi.src_and_vvars if _is_from(src, block)]
    if len(hits) != 1:
        return False, None
    return True, hits[0]


def _twin_mapping(branch, kept, dropped, max_stmts):
    """``{dropped_varid: kept_varid}`` if entering `dropped` from `branch` computes what entering `kept` does.

    Phis pair up in order and must take the same value on the edge from `branch`; the rest must be the same pure
    assignments modulo the renaming.
    """
    kept_all, dropped_all = _real_statements(kept), _real_statements(dropped)
    kept_phis = [s for s in kept_all if _is_phi(s)]
    dropped_phis = [s for s in dropped_all if _is_phi(s)]
    kept_rest = [s for s in kept_all if not _is_phi(s)]
    dropped_rest = [s for s in dropped_all if not _is_phi(s)]
    if len(kept_phis) != len(dropped_phis) or len(kept_rest) > max_stmts:
        return None
    mapping: dict[int, int] = {}
    for k, d in zip(kept_phis, dropped_phis):
        kd, dd = k.dst, d.dst
        if not isinstance(kd, ailment.expression.VirtualVariable) or not isinstance(
            dd, ailment.expression.VirtualVariable
        ):
            return None
        if kd.bits != dd.bits or kd.category != dd.category or kd.oident != dd.oident:
            return None
        k_ok, k_v = _phi_entry(k.src, branch)
        d_ok, d_v = _phi_entry(d.src, branch)
        if not k_ok or not d_ok:
            return None
        if (k_v is None) != (d_v is None) or (k_v is not None and k_v.varid != d_v.varid):
            return None
        if dd.varid in mapping or dd.varid == kd.varid:
            return None
        mapping[dd.varid] = kd.varid
    if not kept_rest and not dropped_rest:
        return mapping
    rest = _equivalent_modulo_renaming(kept_rest, dropped_rest, mapping)
    return rest


def _join_agrees(join_block, kept_block, dropped_block, mapping: dict[int, int]) -> bool:
    """True if every phi at the join takes the same value from both arms, up to `mapping`."""
    for stmt in join_block.statements:
        if not _is_phi(stmt):
            continue
        d_ok, d_v = _phi_entry(stmt.src, dropped_block)
        k_ok, k_v = _phi_entry(stmt.src, kept_block)
        if not d_ok or not k_ok:
            return False
        if d_v is None or k_v is None:
            if d_v is not k_v:
                return False
        elif mapping.get(d_v.varid, d_v.varid) != k_v.varid:
            return False
    return True


def _drop_phi_source(block, source_block, readers, collapse: bool) -> None:
    """Remove `source_block`'s entry from every phi of `block`; with `collapse`, a one-source phi becomes a copy."""
    new_stmts = []
    for stmt in block.statements:
        if _is_phi(stmt) and any(_is_from(src, source_block) for src, _ in stmt.src.src_and_vvars):
            remaining = [(src, vvar) for src, vvar in stmt.src.src_and_vvars if not _is_from(src, source_block)]
            if collapse and len(remaining) == 1 and remaining[0][1] is not None:
                readers.note_read(remaining[0][1].varid, block, False)
                new_stmts.append(ailment.statement.Assignment(stmt.idx, stmt.dst, remaining[0][1], **stmt.tags))
                continue
            new_phi = ailment.expression.Phi(stmt.src.idx, stmt.src.bits, remaining, **stmt.src.tags)
            new_stmts.append(ailment.statement.Assignment(stmt.idx, stmt.dst, new_phi, **stmt.tags))
            continue
        new_stmts.append(stmt)
    block.statements = new_stmts


def _redirect_to_twin(graph, branch, last, kept, dropped, max_stmts, readers, manager) -> bool:
    """Send `branch` to `kept` only, when `dropped` is its twin. `dropped` goes once nothing else enters it.

    Unlike the diamond merge, the arms may hold phis and may have other predecessors: only the edge
    branch -> dropped is removed.
    """
    kept_next = list(graph.successors(kept))
    dropped_next = list(graph.successors(dropped))
    if len(kept_next) != 1 or len(dropped_next) != 1 or kept_next[0] is not dropped_next[0]:
        return False
    join = kept_next[0]
    if join is kept or join is dropped or join is branch or branch is kept or branch is dropped:
        return False
    if not _expr_is_pure(last.condition):
        return False
    mapping = _twin_mapping(branch, kept, dropped, max_stmts)
    if mapping is None:
        return False
    if not readers.only_read_by(mapping, dropped, join):
        return False
    if not _join_agrees(join, kept, dropped, mapping):
        return False

    branch.statements = branch.statements[:-1] + [_jump_to(kept, last, manager)]
    graph.remove_edge(branch, dropped)
    if graph.in_degree(dropped) == 0:
        _drop_phi_source(join, dropped, readers, True)
        graph.remove_node(dropped)
    else:
        _drop_phi_source(dropped, branch, readers, False)
    return True


def merge_duplicate_branches(graph, max_stmts: int = DEFAULT_MAX_DUPLICATED_BRANCH_STMTS, manager=None) -> bool:
    """Merge every if/else in `graph` whose two arms compute the same thing.

    Modifies `graph` in place -- nodes keep their identity, only their statement lists are
    replaced -- and returns True if anything changed.
    """
    merged = 0
    while True:
        # every round that merges removes a conditional jump, so this ends
        n = _merge_round(graph, max_stmts, manager)
        if not n:
            break
        merged += n
    if merged:
        _l.info("DuplicateBranchMerger: merged %d duplicated if/else construct(s)", merged)
    return merged > 0


def _merge_round(graph, max_stmts, manager) -> int:
    merged = 0
    readers = _VVarReaders(graph)
    for branch in list(graph.nodes()):
        if branch not in graph or not branch.statements:
            continue
        last = branch.statements[-1]
        if not isinstance(last, ailment.statement.ConditionalJump):
            continue
        succs = list(graph.successors(branch))
        if len(succs) == 1 and _both_targets_are(last, succs[0]):
            # both arms are the same block: the condition decides nothing
            if not _expr_is_pure(last.condition):
                continue
            branch.statements = branch.statements[:-1] + [_jump_to(succs[0], last, manager)]
            merged += 1
            _l.debug("dropped a conditional jump at %#x whose arms are both %#x", branch.addr, succs[0].addr)
            continue
        if len(succs) != 2 or succs[0] is succs[1]:
            continue

        for kept, dropped in ((succs[0], succs[1]), (succs[1], succs[0])):
            if list(graph.predecessors(dropped)) != [branch]:
                continue  # the arm is reachable another way; removing it would lose that path
            kept_next = list(graph.successors(kept))
            dropped_next = list(graph.successors(dropped))
            if len(kept_next) != 1 or len(dropped_next) != 1 or kept_next[0] is not dropped_next[0]:
                continue
            join = kept_next[0]
            if join is kept or join is dropped or join is branch:
                continue

            kept_stmts = _real_statements(kept)
            dropped_stmts = _real_statements(dropped)
            if len(kept_stmts) > max_stmts:
                continue  # an arm with no statements at all is the N=0 case, and does merge
            mapping = _equivalent_modulo_renaming(kept_stmts, dropped_stmts)
            if mapping is None:
                continue
            if not readers.only_read_by(mapping, dropped, join):
                continue
            repaired = _repair_phis(join, kept, dropped, mapping, readers)
            if repaired is None:
                continue  # a phi at the join really does select between the arms

            # the condition is now dead: branch unconditionally into the surviving arm
            branch.statements = branch.statements[:-1] + [_jump_to(kept, last, manager)]
            join.statements = repaired
            graph.remove_node(dropped)
            merged += 1
            _l.debug(
                "merged duplicate branches at %#x: kept %#x, dropped %#x (%d statements, join %#x)",
                branch.addr, kept.addr, dropped.addr, len(kept_stmts), join.addr,
            )
            break
        else:
            for kept, dropped in ((succs[0], succs[1]), (succs[1], succs[0])):
                if _redirect_to_twin(graph, branch, last, kept, dropped, max_stmts, readers, manager):
                    merged += 1
                    _l.debug("redirected %#x from twin %#x to %#x", branch.addr, dropped.addr, kept.addr)
                    break

    return merged


class DuplicateBranchMerger(OptimizationPass):
    """Collapse if/else constructs whose two arms compute the same thing."""

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Merge if/else branches that compute the same thing"
    DESCRIPTION = (__doc__ or "").strip()

    def __init__(self, *args, max_duplicated_branch_stmts: int | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._max_stmts = (
            DEFAULT_MAX_DUPLICATED_BRANCH_STMTS if max_duplicated_branch_stmts is None else max_duplicated_branch_stmts
        )
        self.analyze()

    def _check(self):
        return self._max_stmts > 0, None

    def _analyze(self, cache=None):  # pylint:disable=unused-argument
        graph = self._graph
        if graph is None:
            return
        if merge_duplicate_branches(graph, self._max_stmts, manager=self.manager):
            self.out_graph = graph

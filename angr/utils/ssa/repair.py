"""Re-establish SSA after a transformation has duplicated blocks.

Passes that clone a block -- switch lowering copying a shared case body, jump
threading, tail duplication -- reproduce the block's assignments verbatim, so a
virtual variable that had exactly one definition ends up with several. Nothing
crashes immediately, because the copies compute the same value from the same
operands, but SSA no longer holds: ``SReachingDefinitions`` and
``GraphDephicationVVarMapping`` key definitions by variable id in a plain dict,
so only the last copy is recorded and everything that reasons about "the"
definition site is then looking at the wrong block.

:func:`repair_multiple_definitions` restores the invariant the standard way
(Cytron et al.): give each extra definition its own variable, place phi nodes at
the iterated dominance frontier of the definition blocks, and rename uses over
the dominator tree so every use reads the version that actually reaches it.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

import networkx

from angr.ailment.block_walker import AILBlockRewriter
from angr.ailment.expression import Phi, VirtualVariable
from angr.ailment.statement import Assignment

from . import is_phi_assignment

if TYPE_CHECKING:
    from angr.ailment import Block
    from angr.ailment.manager import Manager

_l = logging.getLogger(__name__)


class _VVarRenamer(AILBlockRewriter):
    """Replaces virtual variables according to a live varid -> replacement mapping."""

    def __init__(self, mapping: dict[int, VirtualVariable]):
        super().__init__(update_block=False)
        self.mapping = mapping

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        replacement = self.mapping.get(expr.varid)
        return replacement.copy() if replacement is not None else expr


def _collect_definitions(graph) -> dict[int, list[tuple[Block, int]]]:
    definitions: dict[int, list[tuple[Block, int]]] = defaultdict(list)
    for block in graph:
        for stmt_idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                definitions[stmt.dst.varid].append((block, stmt_idx))
    return definitions


def _dominance_frontiers(graph, idom: dict) -> dict:
    """Cytron's dominance frontier, over the graph's own nodes."""
    frontiers: dict = defaultdict(set)
    for block in graph:
        if block not in idom:
            continue
        preds = [p for p in graph.predecessors(block) if p in idom]
        if len(preds) < 2:
            continue
        for pred in preds:
            runner = pred
            while runner is not idom[block] and runner in idom:
                frontiers[runner].add(block)
                nxt = idom[runner]
                if nxt is runner:
                    break
                runner = nxt
    return frontiers


def _iterated_dominance_frontier(def_blocks, frontiers) -> set:
    result: set = set()
    worklist = list(def_blocks)
    queued = set(def_blocks)
    while worklist:
        block = worklist.pop()
        for frontier_block in frontiers.get(block, ()):
            if frontier_block in result:
                continue
            result.add(frontier_block)
            if frontier_block not in queued:
                queued.add(frontier_block)
                worklist.append(frontier_block)
    return result


def repair_multiple_definitions(graph, entry, ail_manager: Manager, vvar_id_start: int, variable_map=None) -> int:
    """Restore SSA for every virtual variable that ``graph`` defines more than once.

    :param graph:           AIL graph to fix up in place.
    :param entry:           Entry block, used to build the dominator tree.
    :param ail_manager:     Supplies fresh AIL object indices.
    :param vvar_id_start:   First virtual variable id free for use.
    :param variable_map:    Optional VariableMap. Passes that run after variable recovery
                            must supply it: a fresh virtual variable with no recovered
                            variable behind it renders as an unsupported instruction.
    :return:                The next unused virtual variable id.
    """
    definitions = _collect_definitions(graph)
    broken = {varid: locs for varid, locs in definitions.items() if len({id(block) for block, _ in locs}) > 1}
    if not broken:
        return vvar_id_start

    # networkx works on the graph's own node objects; angr's Dominators wraps them in
    # TemporaryNodes, which would make the dominator-tree walk below silently visit nothing
    idom = networkx.immediate_dominators(graph, entry)
    frontiers = _dominance_frontiers(graph, idom)
    children: dict = defaultdict(list)
    for block, parent in idom.items():
        if block is not parent:
            children[parent].append(block)

    next_vvar_id = vvar_id_start
    versions: dict[int, dict[int, VirtualVariable]] = {}
    phis: dict[int, list[tuple[int, VirtualVariable]]] = defaultdict(list)
    # inserted phi's own varid -> the original varid it merges
    phi_owner: dict[int, int] = {}

    def _fresh(template: VirtualVariable) -> VirtualVariable:
        nonlocal next_vvar_id
        vvar = VirtualVariable(
            ail_manager.next_atom(),
            next_vvar_id,
            template.bits,
            template.category,
            oident=template.oident,
            **template.tags,
        )
        next_vvar_id += 1
        if variable_map is not None:
            variable_map.transfer(template, vvar)
        return vvar

    for varid, locs in sorted(broken.items()):
        reachable = [(block, stmt_idx) for block, stmt_idx in locs if block in idom]
        if len(reachable) < 2:
            continue
        template = reachable[0][0].statements[reachable[0][1]].dst
        ordered = sorted(
            reachable, key=lambda item: (item[0].addr, -1 if item[0].idx is None else item[0].idx, item[1])
        )

        per_block: dict[int, VirtualVariable] = {}
        for position, (block, stmt_idx) in enumerate(ordered):
            # the first definition keeps the original id so unrelated code needs no rewriting
            per_block[id(block)] = template if position == 0 else _fresh(template)
        versions[varid] = per_block

        for phi_block in _iterated_dominance_frontier({block for block, _ in ordered}, frontiers):
            phi_dst = _fresh(template)
            phi_owner[phi_dst.varid] = varid
            phis[id(phi_block)].append((varid, phi_dst))

    if not versions:
        return next_vvar_id

    _insert_phis(graph, phis, ail_manager)
    _rename(graph, entry, children, versions, phis, phi_owner)
    return next_vvar_id


def _insert_phis(graph, phis, ail_manager: Manager) -> None:
    blocks_by_id = {id(block): block for block in graph}
    for block_id, entries in phis.items():
        block = blocks_by_id[block_id]
        preds = sorted(
            ((p.addr, p.idx) for p in graph.predecessors(block)),
            key=lambda loc: (loc[0], -1 if loc[1] is None else loc[1]),
        )
        # every synthesized object needs its own index: idx=None lands at 0, and the
        # variable map is keyed by index, so they would all collide on one variable
        block.statements = [
            Assignment(
                ail_manager.next_atom(),
                phi_dst,
                Phi(ail_manager.next_atom(), phi_dst.bits, [(pred, None) for pred in preds], **phi_dst.tags),
                **phi_dst.tags,
            )
            for _, phi_dst in entries
        ] + list(block.statements)


def _rename(graph, entry, children, versions, phis, phi_owner) -> None:
    """Dominator-tree walk giving every use the version that reaches it."""
    current: dict[int, VirtualVariable] = {}
    renamer = _VVarRenamer(current)

    def visit(block: Block) -> None:
        pushed: list[tuple[int, VirtualVariable | None]] = []
        block_phis = phis.get(id(block), ())
        for varid, phi_dst in block_phis:
            pushed.append((varid, current.get(varid)))
            current[varid] = phi_dst

        for stmt_idx in range(len(block_phis), len(block.statements)):
            stmt = block.statements[stmt_idx]
            if is_phi_assignment(stmt):
                continue
            versioned = (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.varid in versions
                and id(block) in versions[stmt.dst.varid]
            )
            if versioned:
                # the source reads the incoming version; the destination becomes this block's
                varid = stmt.dst.varid
                new_src = renamer.walk_expression(stmt.src, stmt_idx=stmt_idx, stmt=stmt, block=block)
                new_dst = versions[varid][id(block)]
                block.statements[stmt_idx] = Assignment(stmt.idx, new_dst, new_src, **stmt.tags)
                pushed.append((varid, current.get(varid)))
                current[varid] = new_dst
            else:
                new_stmt = renamer.walk_statement(stmt, block=block, stmt_idx=stmt_idx)
                if new_stmt is not None and new_stmt is not stmt:
                    block.statements[stmt_idx] = new_stmt

        for succ in graph.successors(block):
            _fill_phi_operands(succ, block, current, versions, phi_owner)

        for child in children.get(block, ()):
            visit(child)

        for varid, previous in reversed(pushed):
            if previous is None:
                current.pop(varid, None)
            else:
                current[varid] = previous

    visit(entry)


def _fill_phi_operands(succ, pred, current, versions, phi_owner) -> None:
    """Set the operands of ``succ``'s phis that come in along the ``pred`` edge."""
    pred_loc = (pred.addr, pred.idx)
    for stmt_idx, stmt in enumerate(succ.statements):
        if not is_phi_assignment(stmt):
            continue
        pairs = list(stmt.src.src_and_vvars)
        changed = False
        for i, (src, vvar) in enumerate(pairs):
            if src != pred_loc:
                continue
            # a phi this pass inserted starts with empty operands and merges the variable
            # it was created for; a pre-existing one keeps naming the variable it always did
            varid = phi_owner.get(stmt.dst.varid) if vvar is None else vvar.varid
            if varid is None or varid not in versions:
                continue
            replacement = current.get(varid)
            if replacement is None or (vvar is not None and replacement.varid == vvar.varid):
                continue
            pairs[i] = (src, replacement.copy())
            changed = True
        if changed:
            succ.statements[stmt_idx] = Assignment(
                stmt.idx, stmt.dst, Phi(stmt.src.idx, stmt.src.bits, pairs, **stmt.src.tags), **stmt.tags
            )

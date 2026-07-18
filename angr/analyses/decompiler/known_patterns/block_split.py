"""Utilities for splitting an AIL block into consecutive blocks within a graph.

The Outliner analysis operates at whole-block granularity, while KnownPattern
matches are usually (sub-)statement-level; splitting the anchor block so the
matched span becomes its own block bridges the two.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import Phi
from angr.ailment.statement import Assignment
from angr.utils.ssa import is_phi_assignment

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from angr.ailment.statement import Statement


def rewrite_phi_sources(block: Block, old_src: tuple[int, int | None], new_src: tuple[int, int | None]) -> None:
    """Rewrite phi statements at the top of ``block`` so that entries sourced
    from ``old_src`` are sourced from ``new_src`` instead. Mutates the block's
    statement list in place."""
    for i, stmt in enumerate(block.statements):
        if not is_phi_assignment(stmt):
            continue
        phi = stmt.src
        assert isinstance(phi, Phi)
        if not any(src == old_src for src, _ in phi.src_and_vvars):
            continue
        new_src_and_vvars = [(new_src if src == old_src else src, vvar) for src, vvar in phi.src_and_vvars]
        new_phi = Phi(None, phi.bits, new_src_and_vvars, **phi.tags)
        block.statements[i] = Assignment(None, stmt.dst, new_phi, **stmt.tags)


def split_ail_block(
    graph: networkx.DiGraph,
    block: Block,
    pre_stmts: Sequence[Statement],
    mid_stmts: Sequence[Statement],
    post_stmts: Sequence[Statement],
    block_addr_alloc: Callable[[], int],
) -> tuple[Block | None, Block, Block | None]:
    """Replace ``block`` in ``graph`` with up to three consecutive blocks
    holding ``pre_stmts``, ``mid_stmts``, and ``post_stmts``.

    The first non-empty part keeps the original block identity ``(addr, idx)``
    so that predecessor jump targets (and the at-most-one-block-per-address
    assumption at the function entry) remain valid; each following part is
    placed at a fresh synthetic address obtained from ``block_addr_alloc``.
    When the last part's identity differs from the original, phi statements in
    the successors are rewritten to source from the new last block. Edge data
    is preserved.

    Returns ``(b_pre, b_mid, b_post)`` where ``b_pre``/``b_post`` are None when
    their statement list is empty. ``mid_stmts`` must be non-empty.
    """
    assert mid_stmts

    in_edges = [(u, dict(data)) for u, _, data in graph.in_edges(block, data=True)]
    out_edges = [(v, dict(data)) for _, v, data in graph.out_edges(block, data=True)]

    b_pre: Block | None = None
    if pre_stmts:
        b_pre = Block(block.addr, block.original_size, statements=list(pre_stmts), idx=block.idx)
        b_mid = Block(block_addr_alloc(), 0, statements=list(mid_stmts), idx=None)
    else:
        b_mid = Block(block.addr, block.original_size, statements=list(mid_stmts), idx=block.idx)

    b_post: Block | None = None
    if post_stmts:
        b_post = Block(block_addr_alloc(), 0, statements=list(post_stmts), idx=None)

    graph.remove_node(block)

    parts = [b for b in (b_pre, b_mid, b_post) if b is not None]
    first, last = parts[0], parts[-1]
    for b in parts:
        graph.add_node(b)
    for a, b in zip(parts, parts[1:]):
        graph.add_edge(a, b)

    for u, data in in_edges:
        graph.add_edge(last if u is block else u, first, **data)
    for v, data in out_edges:
        graph.add_edge(last, first if v is block else v, **data)

    if (last.addr, last.idx) != (block.addr, block.idx):
        for succ in graph.successors(last):
            rewrite_phi_sources(succ, (block.addr, block.idx), (last.addr, last.idx))

    return b_pre, b_mid, b_post

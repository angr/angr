"""Turn a token interval into something :class:`~angr.analyses.outliner.Outliner` accepts.

The Outliner takes a single entry location plus a frontier and lifts everything
between them into a new function. A token interval discovered by :mod:`.align`
does not automatically satisfy that: it may start or end in the middle of a
block, and the blocks it covers may be entered from outside.

:func:`snap` reports whether an interval can be outlined and why not when it
cannot; :func:`materialize` performs the block splits and returns the final
``(src_loc, frontier)``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .align import Interval

if TYPE_CHECKING:
    import networkx

    from angr.ailment import Block

    from .tokenizer import TokenStream

_l = logging.getLogger(__name__)

Address = tuple[int, "int | None"]


@dataclass
class Region:
    """An interval mapped onto AIL blocks, with its outlinability verdict."""

    interval: Interval
    block_locs: list[Address]
    src_loc: Address
    frontier: set[Address] = field(default_factory=set)
    head_split: int = 0
    tail_split: int = 0
    outlinable: bool = False
    reason: str = ""

    @property
    def needs_split(self) -> bool:
        return self.head_split > 0 or self.tail_split > 0


def snap(
    stream: TokenStream,
    graph: networkx.DiGraph[Block],
    interval: Interval,
    *,
    allow_split: bool = True,
    entry_loc: Address | None = None,
) -> Region:
    """Map ``interval`` onto blocks and decide whether the Outliner can take it."""
    block_locs = stream.block_locs_in(interval.start, interval.end)
    if not block_locs:
        return Region(interval, [], (0, None), reason="interval covers no blocks")

    first, last = block_locs[0], block_locs[-1]
    head_split = interval.start - stream.block_span[first][0]
    tail_split = stream.block_span[last][1] - interval.end

    region = Region(
        interval=interval,
        block_locs=block_locs,
        src_loc=first,
        head_split=head_split,
        tail_split=tail_split,
    )

    if not allow_split and region.needs_split:
        region.reason = "interval is not block-aligned and splitting is disabled"
        return region

    nodes = {(b.addr, b.idx): b for b in graph}
    missing = [loc for loc in block_locs if loc not in nodes]
    if missing:
        region.reason = f"blocks {missing[:3]} are not in the graph"
        return region

    member = set(block_locs)
    # after a head split the region starts at a fresh block, so the original
    # block's outside predecessors land on the pre-part, not on the region
    for loc in block_locs:
        if loc == first:
            continue
        for pred in graph.predecessors(nodes[loc]):
            if (pred.addr, pred.idx) not in member:
                region.reason = f"block {loc[0]:#x} is entered from outside the region"
                return region

    if entry_loc is not None and entry_loc in member and entry_loc != first:
        region.reason = "region contains the function entry but does not start at it"
        return region

    frontier: set[Address] = set()
    for loc in block_locs:
        for succ in graph.successors(nodes[loc]):
            succ_loc = (succ.addr, succ.idx)
            if succ_loc not in member:
                frontier.add(succ_loc)

    region.frontier = frontier
    if not frontier:
        region.reason = "region has no exit (it would swallow the function tail)"
        return region

    region.outlinable = True
    region.reason = "ok"
    return region


def materialize(
    graph: networkx.DiGraph[Block],
    stream: TokenStream,
    region: Region,
    block_addr_alloc: Callable[[], int],
    *,
    split_tail: bool = True,
) -> tuple[Address, set[Address]]:
    """Split the boundary blocks in place so ``region`` becomes block-aligned.

    Returns the ``(src_loc, frontier)`` pair to hand to the Outliner. ``graph``
    is mutated. With ``split_tail=False`` only the head is split, which is what
    the caller wants when it intends to let the Outliner derive its own
    frontier: the tail boundary is then chosen by liveness, not by the interval.
    """
    from angr.analyses.decompiler.known_patterns.block_split import split_ail_block

    nodes = {(b.addr, b.idx): b for b in graph}
    first_loc, last_loc = region.block_locs[0], region.block_locs[-1]
    src_loc = region.src_loc
    frontier = set(region.frontier)

    head_stmt = stream.locs[region.interval.start].stmt_idx
    tail_stmt = stream.locs[region.interval.end - 1].stmt_idx + 1

    tail_split = region.tail_split if split_tail else 0

    if first_loc == last_loc:
        if region.head_split == 0 and tail_split == 0:
            return src_loc, frontier
        block = nodes[first_loc]
        stmts = list(block.statements)
        mid_stmts = stmts[head_stmt:tail_stmt] if split_tail else stmts[head_stmt:]
        post_stmts = stmts[tail_stmt:] if split_tail else []
        _pre, mid, post = split_ail_block(graph, block, stmts[:head_stmt], mid_stmts, post_stmts, block_addr_alloc)
        src_loc = (mid.addr, mid.idx)
        if post is not None:
            frontier.add((post.addr, post.idx))
        return src_loc, frontier

    if region.head_split > 0:
        block = nodes[first_loc]
        stmts = list(block.statements)
        _pre, mid, _post = split_ail_block(graph, block, stmts[:head_stmt], stmts[head_stmt:], [], block_addr_alloc)
        src_loc = (mid.addr, mid.idx)

    if tail_split > 0:
        block = nodes[last_loc]
        stmts = list(block.statements)
        _pre, _mid, post = split_ail_block(graph, block, [], stmts[:tail_stmt], stmts[tail_stmt:], block_addr_alloc)
        if post is not None:
            frontier.discard(last_loc)
            frontier.add((post.addr, post.idx))

    return src_loc, frontier

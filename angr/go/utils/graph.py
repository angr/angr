from __future__ import annotations

from typing import TYPE_CHECKING

from angr.ailment.statement import ConditionalJump, Jump, Label

if TYPE_CHECKING:
    import networkx

    from angr.ailment.block import Block


def is_jump_only(block: Block) -> bool:
    return all(isinstance(stmt, (Label, Jump)) for stmt in block.statements)


def conditional_pred(graph: networkx.DiGraph, block: Block) -> Block | None:
    """The block whose conditional jump leads to ``block``, looking through trampoline (jump-only) blocks."""
    seen = set()
    while True:
        preds = list(graph.predecessors(block))
        if len(preds) != 1 or preds[0] in seen:
            return None
        block = preds[0]
        seen.add(block)
        if block.statements and isinstance(block.statements[-1], ConditionalJump):
            return block
        if not is_jump_only(block):
            return None


def skip_jumps(graph: networkx.DiGraph, block: Block) -> Block:
    """Follow trampoline blocks until a block that does something."""
    seen = set()
    while block not in seen and is_jump_only(block):
        seen.add(block)
        succs = list(graph.successors(block))
        if len(succs) != 1:
            break
        block = succs[0]
    return block


def leads_to(graph: networkx.DiGraph, block: Block, target: Block) -> bool:
    """Whether ``block`` is ``target`` or a trampoline chain ending at it."""
    seen = set()
    while block is not target and block not in seen and is_jump_only(block):
        seen.add(block)
        succs = list(graph.successors(block))
        if len(succs) != 1:
            return False
        block = succs[0]
    return block is target


def block_before(graph: networkx.DiGraph, block: Block, target: Block) -> Block | None:
    """The last block of the trampoline chain from ``block`` to ``target`` (``block`` itself when it is adjacent)."""
    seen = set()
    while block is not target and block not in seen:
        seen.add(block)
        succs = list(graph.successors(block))
        if len(succs) != 1 or not is_jump_only(block):
            return None
        if succs[0] is target:
            return block
        block = succs[0]
    return None

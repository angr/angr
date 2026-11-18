from __future__ import annotations

import networkx

from angr.ailment import Block
from angr.analyses.decompiler.ailgraph_walker import traverse_in_order


def test_traverse_in_order_visits_disconnected_component():
    entry = Block(0)
    entry_successor = Block(1)
    loop_head = Block(2)
    loop_tail = Block(3)
    loop_successor = Block(4)
    graph = networkx.DiGraph(
        [
            (entry, entry_successor),
            (loop_head, loop_tail),
            (loop_tail, loop_head),
            (loop_tail, loop_successor),
        ]
    )
    visited: list[Block] = []

    traverse_in_order(graph, [entry], visited.append)

    assert visited[:2] == [entry, entry_successor]
    assert set(visited) == set(graph)
    assert visited.index(loop_head) < visited.index(loop_successor)
    assert visited.index(loop_tail) < visited.index(loop_successor)

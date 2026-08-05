from __future__ import annotations

import networkx as nx
import pytest

from angr.ailment import BinaryOp, Block, Const, Register
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.optimization_passes.duplication_reverter.errors import UnsupportedAILNodeError
from angr.analyses.decompiler.optimization_passes.duplication_reverter.utils import bfs_list_blocks


def test_bfs_list_blocks_rejects_nonconditional_branch():
    source = Block(0x400000, 1, statements=[Jump(0, Register(0, 0, 64))])
    child_0 = Block(0x400010, 1)
    child_1 = Block(0x400020, 1)
    graph = nx.DiGraph([(source, child_0), (source, child_1)])

    with pytest.raises(UnsupportedAILNodeError, match=r"Block 0x400000 has two successors but ends in Jump"):
        bfs_list_blocks(source, graph)


def test_bfs_list_blocks_visits_true_successor_first():
    condition = BinaryOp(0, "CmpEQ", [Register(0, 0, 64), Const(0, 0, 64)], False)
    true_child = Block(0x400010, 1)
    false_child = Block(0x400020, 1)
    source = Block(
        0x400000,
        1,
        statements=[ConditionalJump(0, condition, Const(0, true_child.addr, 64), Const(0, false_child.addr, 64))],
    )
    graph = nx.DiGraph([(source, false_child), (source, true_child)])

    assert bfs_list_blocks(source, graph) == [source, true_child, false_child]

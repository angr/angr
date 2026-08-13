from __future__ import annotations

import unittest

import networkx as nx

from angr import ailment
from angr.analyses.decompiler.utils import to_ail_supergraph


class TestDecompilerUtils(unittest.TestCase):
    def test_supergraph_preserves_control_flow_order_when_addresses_run_backwards(self):
        predecessor = ailment.Block(
            0x4000,
            4,
            statements=[
                ailment.Stmt.Assignment(
                    0,
                    ailment.Expr.Register(0, 0, 64),
                    ailment.Expr.Const(0, 1, 64),
                ),
                ailment.Stmt.Jump(1, ailment.Expr.Const(1, 0x3000, 64)),
            ],
        )
        conditional = ailment.Block(
            0x3000,
            4,
            statements=[
                ailment.Stmt.ConditionalJump(
                    2,
                    ailment.Expr.Const(2, 1, 1),
                    ailment.Expr.Const(3, 0x2000, 64),
                    ailment.Expr.Const(4, 0x1000, 64),
                )
            ],
        )
        true_target = ailment.Block(0x2000, 4, statements=[ailment.Stmt.Return(3, [])])
        false_target = ailment.Block(0x1000, 4, statements=[ailment.Stmt.Return(4, [])])
        graph = nx.DiGraph(
            [
                (predecessor, conditional),
                (conditional, true_target),
                (conditional, false_target),
            ]
        )

        result = to_ail_supergraph(graph, allow_fake=True)

        merged = next(node for node in result if node.addr == predecessor.addr)
        self.assertEqual(len(result), 3)
        self.assertIsInstance(merged.statements[0], ailment.Stmt.Assignment)
        self.assertIsInstance(merged.statements[-1], ailment.Stmt.ConditionalJump)
        self.assertEqual(set(result.successors(merged)), {true_target, false_target})


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import unittest

import networkx as nx

from angr import Project, ailment
from angr.analyses.decompiler import Decompiler
from angr.analyses.decompiler.utils import to_ail_supergraph
from tests.common import bin_location

COREUTILS_SUM = os.path.join(bin_location, "tests", "x86_64", "decompiler", "coreutils_sum_O2")


class TestDecompilerUtils(unittest.TestCase):
    """Tests for shared decompiler graph utilities."""

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

    @unittest.skipUnless(os.path.isfile(COREUTILS_SUM), f"missing test binary: {COREUTILS_SUM}")
    def test_supergraph_statement_order_coreutils_sum(self):
        project = Project(COREUTILS_SUM, auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
        function = cfg.kb.functions[0x402780]
        self.assertEqual(function.name, "main")

        decompilation = project.analyses[Decompiler].prep(fail_fast=True)(
            function,
            cfg=cfg.model,
            preset="full",
            options=[("structurer_cls", "sailr")],
            use_cache=False,
        )

        assert decompilation.codegen is not None
        self.assertIsNotNone(decompilation.codegen.text)


if __name__ == "__main__":
    unittest.main()

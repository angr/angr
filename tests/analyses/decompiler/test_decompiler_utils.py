# pylint:disable=protected-access

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from angr import Project
from angr.ailment.statement import Jump
from angr.analyses.decompiler import Decompiler
from angr.analyses.decompiler import utils as decompiler_utils
from tests.common import bin_location

COREUTILS_SUM = os.path.join(bin_location, "tests", "x86_64", "decompiler", "coreutils_sum_O2")


class TestDecompilerUtils(unittest.TestCase):
    """Tests for shared decompiler graph utilities."""

    @unittest.skipUnless(os.path.isfile(COREUTILS_SUM), f"missing test binary: {COREUTILS_SUM}")
    def test_supergraph_statement_order_coreutils_sum(self):
        project = Project(COREUTILS_SUM, auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
        function = cfg.kb.functions[0x402780]
        self.assertEqual(function.name, "main")

        original_merge = decompiler_utils._merge_ail_nodes
        observed_merges = 0

        def checked_merge(graph, node_a, node_b):
            nonlocal observed_merges
            node_a_statements = list(node_a.statements)
            node_b_statements = list(node_b.statements)
            merged = original_merge(graph, node_a, node_b)

            if node_a.addr == 0x402A5F and node_b.addr == 0x402900:
                observed_merges += 1
                expected_statements = (
                    node_a_statements[:-1]
                    if node_a_statements and isinstance(node_a_statements[-1], Jump)
                    else node_a_statements
                )
                expected_statements += node_b_statements
                self.assertEqual((merged.addr, merged.idx), (node_a.addr, node_a.idx))
                self.assertEqual(merged.statements, expected_statements)

            return merged

        with patch.object(decompiler_utils, "_merge_ail_nodes", side_effect=checked_merge):
            decompilation = project.analyses[Decompiler].prep(fail_fast=True)(
                function,
                cfg=cfg.model,
                preset="full",
                options=[("structurer_cls", "sailr")],
                use_cache=False,
            )

        assert decompilation.codegen is not None
        self.assertGreater(observed_merges, 0)


if __name__ == "__main__":
    unittest.main()

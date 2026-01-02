# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations
import unittest
import os

import angr

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestKillingRefs(unittest.TestCase):
    def test_killing_refs(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "test_killing_ref"), auto_load_libs=False)
        p.analyses.CFGFast(normalize=True)
        dec = p.analyses.Decompiler(p.kb.functions["main"])
        assert dec.clinic is not None
        assert dec.clinic.graph is not None
        srda = p.analyses.SReachingDefinitions(p.kb.functions["main"], func_graph=dec.clinic.graph)
        blocks = {(block.addr, block.idx): block for block in dec.clinic.graph}

        # there should be a new vvar for the second snprintf destination. Neither vvar should be an extern.
        assert (
            sum(
                not defloc.is_extern
                and "Call(0x401050" in str(blocks[(defloc.block_addr, defloc.block_idx)].statements[defloc.stmt_idx])
                for _, defloc in srda.model.all_vvar_definitions.items()
            )
            == 2
        )


if __name__ == "__main__":
    unittest.main()

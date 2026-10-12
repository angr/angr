#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestPhoenixBackEdgeNodes(unittest.TestCase):
    """
    Acyclic schemas must match nodes that have an edge to the region head, but must not absorb the region head.
    """

    def test_mirai_killer_kill_by_port(self):
        # after cyclic refinement, a node of the /proc/net/tcp loop either continues or runs
        # `util_strcpy(...); break;`. that node has an edge to the region head.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "decbench_mirai_O2_noinline")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions.function(name="killer_kill_by_port")
        assert func is not None

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert not dec.structuring_failures

        text = dec.codegen.text
        # code after the /proc/net/tcp loop is present
        assert "Found inode" in text
        assert "Failed to find inode" in text
        assert "[killer] Found pid" in text
        # both exits of the loop to close(fd) at 0x4070bc are breaks
        assert "LABEL_4070bc" not in text


if __name__ == "__main__":
    unittest.main()

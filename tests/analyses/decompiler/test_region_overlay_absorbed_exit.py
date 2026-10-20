#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestRegionOverlayAbsorbedExit(unittest.TestCase):
    def test_absorbed_branch_keeps_the_if_else_exit(self):
        # copy() has the loop shape of coreutils cat(): two early-return branches share a tail block that is the
        # exit of the enclosing loop. The if/else matcher re-establishes the tail as the if/else node's successor
        # for one branch, then absorbs the other; RegionOverlay.remove_node() used to hide the rewired pair, which
        # was that very successor edge, so the loop lost its only exit and could not be structured.
        proj = angr.Project(
            os.path.join(test_location, "x86_64", "decompiler", "cat_shape_stripped"), auto_load_libs=False
        )
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        dec = proj.analyses.Decompiler(proj.kb.functions[0x401280], cfg=cfg.model)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "while (1)" in text
        assert text.count("return") == 2


if __name__ == "__main__":
    unittest.main()

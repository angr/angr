#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestProximityGraph(unittest.TestCase):
    def test_fauxware(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(data_references=True, cross_references=True, normalize=True)
        func = cfg.kb.functions["main"]

        proj.analyses.Proximity(func, cfg.model, cfg.kb.xrefs)

        # once we have decompiled code, things are different...
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        proj.analyses.Proximity(func, cfg.model, cfg.kb.xrefs, decompilation=dec)


if __name__ == "__main__":
    unittest.main()

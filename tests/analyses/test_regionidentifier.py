#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestRegionIdentifier(unittest.TestCase):
    def test_smoketest(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)
        cfg = p.analyses.CFG(normalize=True)

        main_func = cfg.kb.functions["main"]

        _ = p.analyses.RegionIdentifier(main_func)

    def test_make_supergraph_update_entrynode(self):
        proj = angr.Project(
            os.path.join(
                test_location, "i386", "windows", "a71a3c3b922705cb5e2d8aa9c74f5c73c47fb27f10b1327eb2bb054d99a14397"
            ),
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFG(
            force_smart_scan=False,
            normalize=True,
            show_progressbar=True,
            regions=[(0x5E4746, 0x5E4910)],
            start_at_entry=False,
            function_starts=(0x5E47CA,),
        )

        the_func = cfg.kb.functions[0x5E47CA]

        # region identifier is invoked during decompilation of this function. shall not fail
        dec = proj.analyses.Decompiler(the_func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen.text


if __name__ == "__main__":
    unittest.main()

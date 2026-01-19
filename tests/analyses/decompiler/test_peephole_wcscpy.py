#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr

from tests.common import bin_location, print_decompilation_result, WORKER

test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestPeepholeWcscpy(unittest.TestCase):
    def test_ipnathlp_IcsRegReadFromLocation(self):
        bin_path = os.path.join(test_location, "x86_64", "windows", "ipnathlp.dll")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)

        # since we are computing the CFG here, let's also ensure XFG hashes are not marked as code
        assert cfg._seg_list.is_occupied(0x18000A798) is True
        assert cfg._seg_list.occupied_by_sort(0x18000A798) == "alignment"
        assert cfg._seg_list.is_occupied(0x18000A79F) is True
        assert cfg._seg_list.occupied_by_sort(0x18000A79F) == "alignment"

        func = cfg.functions[0x18003CA70]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert (
            'L"System\\\\CurrentControlSet\\\\Services\\\\Tcpip6\\\\Parameters\\\\Interfaces\\\\", 63)'
            in dec.codegen.text
        )

    def test_snap_non_consecutive_wcscpy_consolidation(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "9c75d43ec531c76caa65de86dcac0269d6727ba4ec74fe1cac1fda0e176fd2ab"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(fail_fast=True, force_smart_scan=False, show_progressbar=not WORKER, normalize=True)
        func = cfg.functions[0x14000FB60]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert 'L"Sub-layer for use by Sophos DNS Inspection"' in dec.codegen.text
        assert 'L"Sophos NTP DNS Sublayer"' in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

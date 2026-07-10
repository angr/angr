#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestPeepholeWcscpy(unittest.TestCase):
    def test_ipnathlp_IcsRegReadFromLocation(self):
        bin_path = os.path.join(test_location, "x86_64", "windows", "ipnathlp.dll")
        proj = angr.Project(bin_path, auto_load_libs=False)

        # the extra region covers the XFG hash at 0x18000a798 that the assertions below rely on
        cfg = proj.analyses.CFGFast(
            normalize=True,
            regions=[(0x18000A780, 0x18000A7C0), (0x18003CA70, 0x18003CA70 + 0x4000)],
            start_at_entry=False,
            function_starts=[0x18003CA70],
            force_smart_scan=True,
        )

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
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x14000FB60, run_ccc=False)
        func = cfg.functions[0x14000FB60]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert 'L"Sub-layer for use by Sophos DNS Inspection"' in dec.codegen.text
        assert 'L"Sophos NTP DNS Sublayer"' in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

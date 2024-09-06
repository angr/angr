#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,arguments-differ,unused-argument
from __future__ import annotations

__package__ = __package__ or "tests.sim"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestSymbolHookedBy(unittest.TestCase):
    def test_hook_symbol(self):
        """
        Test the hook_symbol (and related functions) using the inet_ntoa simprocedure for functionality
        """
        bin_path = os.path.join(test_location, "x86_64", "inet_ntoa")
        proj = angr.Project(bin_path, auto_load_libs=False, use_sim_procedures=True)

        assert proj.is_symbol_hooked("inet_ntoa")
        assert not proj.is_symbol_hooked("not_expected_to_exist")

        original_hook = proj.symbol_hooked_by("inet_ntoa")

        assert isinstance(original_hook, angr.SIM_PROCEDURES["posix"]["inet_ntoa"])

        # No intention to call this, just checking hooking
        class FakeInetNtoa(angr.SimProcedure):
            def run(self, in_addr):
                return None

        fake_inet_ntoa = FakeInetNtoa()

        # test not allowing replacement
        proj.hook_symbol("inet_ntoa", fake_inet_ntoa, replace=False)
        assert proj.symbol_hooked_by("inet_ntoa") == original_hook

        # test allowing replacement
        proj.hook_symbol("inet_ntoa", fake_inet_ntoa, replace=True)
        assert proj.symbol_hooked_by("inet_ntoa") != original_hook
        assert proj.symbol_hooked_by("inet_ntoa") == fake_inet_ntoa


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location, slow_test


test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCfgRustGotResolution(unittest.TestCase):
    @slow_test
    def test_rust_got_resolution(self):
        # Test a simple Rust binary sample.
        #
        # Rust compiler may insert some non-external functions into GOT.
        # This tests whether angr can resolve indirect function calls to GOT entries in Rust binaries.

        path = os.path.join(test_location, "x86_64", "rust_hello_world")
        p = angr.Project(path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(resolve_indirect_jumps=True)

        # angr should be able to resolve the indirect call in main function
        main = cfg.kb.functions[p.loader.find_symbol("_ZN16rust_hello_world4main17h932c4676a11c63c3E").rebased_addr]
        assert not main.has_unresolved_calls


if __name__ == "__main__":
    unittest.main()

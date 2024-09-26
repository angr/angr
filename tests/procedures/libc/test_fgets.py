#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ...common import bin_location


class TestFgets(unittest.TestCase):
    TARGET_APP = os.path.join(bin_location, "tests", "x86_64", "fgets")

    def setUp(self):
        self.p = angr.Project(TestFgets.TARGET_APP, auto_load_libs=False)

        self.find_normal = self.p.loader.find_symbol("find_normal").rebased_addr
        self.find_exact = self.p.loader.find_symbol("find_exact").rebased_addr
        self.find_eof = self.p.loader.find_symbol("find_eof").rebased_addr
        self.find_impossible = self.p.loader.find_symbol("find_impossible").rebased_addr

    def _testfind(self, addr, failmsg):
        e = self.p.factory.entry_state()
        e.options.add(angr.sim_options.SHORT_READS)
        e.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        s = self.p.factory.simgr(e)
        r = s.explore(find=addr)
        assert len(r.found) > 0, failmsg
        return r.found[0].posix.dumps(0)

    def _testnotfind(self, addr, failmsg):
        e = self.p.factory.entry_state()
        e.options.add(angr.sim_options.SHORT_READS)
        e.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        s = self.p.factory.simgr(e)
        r = s.explore(find=addr)
        assert len(r.found) == 0, failmsg

    def test_normal(self):
        answer = self._testfind(self.find_normal, "Normal Failure!")
        assert answer == b"normal\n"

    def test_exact(self):
        answer = self._testfind(self.find_exact, "Exact Failure!")
        assert answer.endswith(b"0123456789")

    def test_impossible(self):
        self._testnotfind(self.find_impossible, "Impossible Failure!")


if __name__ == "__main__":
    unittest.main()

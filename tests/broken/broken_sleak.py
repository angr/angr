#!/usr/bin/env python
from __future__ import annotations

import angr
import os
import nose

p32 = None
p64 = None


def setup_module():
    global p32, p64
    test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
    bin64 = os.path.join(test_location, "x86_64", "all")
    bin32 = os.path.join(test_location, "i386", "all")

    p32 = angr.Project(bin64)
    p64 = angr.Project(bin32)


def run_xpl(p):
    a = p.analyses.XSleak(num_leaks=3)
    a.run()
    nose.tools.assert_equal(len(a.leaks), 3)


def run_slice(p):
    a = p.analyses.Sleakslice()
    a.run()
    nose.tools.assert_equal(len(a.leaks), 3)


def test_xpl_32():
    run_xpl(p32)


def test_xpl_64():
    run_xpl(p64)


def test_slice_32():
    run_slice(p32)


def test_slice_64():
    run_slice(p64)


if __name__ == "__main__":
    test_xpl_32()
    test_xpl_64()
    test_slice_32()
    test_slice_64()

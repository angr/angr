#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

# from ..common import bin_location
bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries")

test_location = os.path.join(bin_location, "tests")


class TestPropagatorStates(unittest.TestCase):
    def test_propagator_states(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "test_load_registers"), auto_load_libs=False)
        cfg = proj.analyses.CFG()
        func = proj.kb.functions["_ZN9AP_Motors5armedEb"]

        prop = proj.analyses.Propagator(func=func, reg_values={"rdi": 0xC0000000})
        xrefs = proj.analyses.XRefs(func=func, replacements=prop.replacements)
        self.assertTrue(any(x.type == 2 for x in list(proj.kb.xrefs.xrefs_by_dst[0xC0000018])))


if __name__ == "__main__":
    unittest.main()

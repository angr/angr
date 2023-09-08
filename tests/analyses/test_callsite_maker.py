#!/usr/bin/env python3
__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import ailment

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCallsiteMaker(unittest.TestCase):
    def test_callsite_maker(self):
        project = angr.Project(
            os.path.join(test_location, "x86_64", "all"),
            auto_load_libs=False,
        )

        manager = ailment.Manager(arch=project.arch)

        # Generate a CFG
        cfg = project.analyses.CFG()

        new_cc_found = True
        while new_cc_found:
            new_cc_found = False
            for func in cfg.kb.functions.values():
                if func.calling_convention is None:
                    # determine the calling convention of each function
                    project.analyses.VariableRecoveryFast(func)
                    cc_analysis = project.analyses.CallingConvention(func)
                    if cc_analysis.cc is not None:
                        func.calling_convention = cc_analysis.cc
                        func.prototype = cc_analysis.prototype
                        new_cc_found = True

        main_func = cfg.kb.functions["main"]

        for block in sorted(main_func.blocks, key=lambda x: x.addr):
            print(block.vex.pp())
            ail_block = ailment.IRSBConverter.convert(block.vex, manager)
            simp = project.analyses.AILBlockSimplifier(ail_block, main_func.addr)

            csm = project.analyses.AILCallSiteMaker(simp.result_block)
            if csm.result_block:
                ail_block = csm.result_block
                simp = project.analyses.AILBlockSimplifier(ail_block, main_func.addr)

            print(simp.result_block)


if __name__ == "__main__":
    unittest.main()

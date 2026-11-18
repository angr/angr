# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import os
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


class TestMipsGpPrologue(unittest.TestCase):
    def test_interleaved_gp_setup_mips64(self):
        # ldexpf sets $gp with lui/daddu/daddiu spread over the first 15 prologue instructions; stopping the scan
        # after the lui used to record a partial $gp
        bin_path = os.path.join(test_location, "mips64", "libc.so.6")
        proj, _ = load_project_with_scoped_cfg(bin_path, 0x453290, expand_call_tree=False, run_ccc=False)
        f = proj.kb.functions[0x453290]
        assert f.info["gp"] == 0x5B7810

    def test_statement_evaluation_matches_symbolic_stepping(self):
        for binary, main_gp in (("mipsel/fauxware", 0x418CA0), ("mips/fauxware", None)):
            proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
            cfg = proj.analyses.CFGFast(show_progressbar=False)
            if main_gp is not None:
                assert cfg.functions["main"].info["gp"] == main_gp
            decided = 0
            for func in cfg.functions.values():
                if func.is_simprocedure or func.is_plt:
                    continue
                irsb = proj.factory.block(func.addr, opt_level=1, cross_insn_opt=False).vex
                fast = cfg._mips_determine_function_gp(func.addr, irsb, func.addr)
                with mock.patch.object(CFGFast, "_mips_gp_from_statements", return_value=(False, None)):
                    symbolic = cfg._mips_determine_function_gp(func.addr, irsb, func.addr)
                assert fast == symbolic, (binary, hex(func.addr))
                decided += fast is not None
            assert decided > 0


if __name__ == "__main__":
    unittest.main()

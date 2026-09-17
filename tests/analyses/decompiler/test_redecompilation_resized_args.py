# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

import angr
from tests.common import WORKER, bin_location

test_location = os.path.join(bin_location, "tests")


class TestRedecompilationResizedArgs(unittest.TestCase):
    """
    Re-decompiling a function after one of its callees was decompiled re-registers its argument variables under the
    same idents (arg_N) but potentially with a different size. In such cases, the old variable must be removed first to
    avoid conflicts.
    """

    def test_redecompile_after_callee_decompilation(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "2ac79168ca17bfdbf70b591dc681114afc29f09aba0df978c3a7db6ed69a3b59"
        )
        func_addr = 0x18005E870
        callee_addr = 0x18006BEA8
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(
            normalize=True,
            regions=[(func_addr, 0x18005E9D5), (callee_addr, 0x18006BF73)],
            function_starts=[func_addr, callee_addr],
            start_at_entry=False,
            show_progressbar=not WORKER,
        )
        proj.analyses.CompleteCallingConventions(
            workers=0, prioritize_func_addrs=[func_addr, callee_addr], skip_other_funcs=True
        )

        proj.analyses.Decompiler(func_addr, cfg=cfg.model, fail_fast=True)
        proj.analyses.Decompiler(callee_addr, cfg=cfg.model, fail_fast=True)
        var_manager = proj.kb.dec_variables[func_addr]
        old_arg0 = var_manager._ident_to_variable["arg_0"]
        assert old_arg0.size == 4

        dec = proj.analyses.Decompiler(func_addr, cfg=cfg.model, fail_fast=True, use_cache=False)
        assert dec.codegen is not None and dec.codegen.text is not None

        # the narrowed argument replaced the stale one instead of sitting next to it
        arg0_vars = [v for v in var_manager.get_variables("reg") if v.ident == "arg_0"]
        assert len(arg0_vars) == 1
        assert arg0_vars[0].size == 1
        assert [v for v in var_manager.get_unified_variables("reg") if v.ident == "arg_0"] == [
            var_manager.unified_variable(arg0_vars[0])
        ]
        assert old_arg0 not in var_manager.find_variables_by_register("rcx")


if __name__ == "__main__":
    unittest.main()

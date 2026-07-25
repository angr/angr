#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestRegisterSaveAreaSimplifierAdv(unittest.TestCase):
    def test_reg_save_area_simplifier_removing_final_func_args(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "131252a8059fdbb12d77cd4711e597c45bb48e6d4bc3ddc808697a5e0488ff2c"
        )
        # A whole-binary CFG of this 3800-function PE costs ~25s while the decompilation itself takes half a
        # second, so scope CFG recovery. The scope covers the function under test, sub_46aae0, the two functions
        # that reach it (calling-convention recovery of a function with a register save area inspects its call
        # sites), and one round of call-tree expansion: only the prototypes of the direct callees influence the
        # output here, and the decompilation text is byte-identical to the whole-binary run.
        proj, cfg = load_project_with_scoped_cfg(
            bin_path,
            0x46A6C0,
            extra_func_addrs=[0x46AAE0, 0x469F80, 0x46AA98],
            call_tree_depth=1,
            project_kwargs={"auto_load_libs": False},
            cfg_kwargs={"fail_fast": True},
            ccc_kwargs={"fail_fast": True},
        )

        callee = cfg.functions[0x46AAE0]
        func = cfg.functions[0x46A6C0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        # should not crash
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert f"{callee.name}(" in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

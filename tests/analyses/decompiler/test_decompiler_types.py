# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
import re

import angr

from tests.common import bin_location, WORKER, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDecompilerTypes(unittest.TestCase):
    def test_mapping_int64_to_basic_type(self):
        proj = angr.Project(
            os.path.join(
                test_location, "x86_64", "windows", "7995a0325b446c462bdb6ae10b692eee2ecadd8e888e9d7729befe4412007afb"
            ),
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFG(
            normalize=True,
            show_progressbar=True,
            regions=[(0x14004C100, 0x14004C100 + 0x1000)],
            start_at_entry=False,
        )

        func = proj.kb.functions[0x14004C100]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None

        # these prototypes are created when decompiling the function above (their caller)
        proto_0 = proj.kb.functions[0x1402004F8].prototype
        assert proto_0 is not None
        assert proto_0.args
        assert proto_0.args[0].size is not None and proto_0.args[0].size > 0
        proto_1 = proj.kb.functions[0x140200518].prototype
        assert proto_1 is not None
        assert proto_1.args
        assert proto_1.args[-1].size is not None and proto_1.args[-1].size > 0

    def test_guid_stackvar_assignment(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "03fb29dab8ab848f15852a37a1c04aa65289c0160d9200dceff64d890b3290dd"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        func = cfg.functions[0x132B0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # find the Guid variable
        guid_var = re.search(r"Guid (?P<var>v\d+);", dec.codegen.text)
        assert guid_var is not None
        guid_varname = guid_var.group("var")

        assert f"{guid_varname}.Data1 = " in dec.codegen.text
        assert f"{guid_varname}.Data2 = " in dec.codegen.text
        assert f"{guid_varname}.Data3 = " in dec.codegen.text
        for i in range(8):
            assert f"{guid_varname}.Data4[{i}] = " in dec.codegen.text


if __name__ == "__main__":
    unittest.main()

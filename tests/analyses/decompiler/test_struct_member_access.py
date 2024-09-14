#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from angr import default_cc

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestStructMemberAccess(unittest.TestCase):
    def test_struct_member_write(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_member_access")
        proj = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = proj.analyses.CFG(data_references=True, normalize=True)

        main_func = cfg.functions["main"]
        foo_func = cfg.functions["foo"]

        angr.types.register_types(angr.types.parse_type("struct Inner {long long a; int b;}"))
        angr.types.register_types(angr.types.parse_type("struct Outer {char* a; struct Inner b;}"))

        foo_func.calling_convention = default_cc(
            proj.arch.name, platform=proj.simos.name if proj.simos is not None else None
        )(proj.arch)
        foo_func.prototype = angr.types.parse_type("void (struct Outer *a)").with_arch(proj.arch)

        dec = proj.analyses.Decompiler(main_func, cfg=cfg)
        text = dec.codegen.text
        assert '.a = "123"' in text
        assert ".b.a = 2" in text
        assert ".b.b = 3" in text


if __name__ == "__main__":
    unittest.main()

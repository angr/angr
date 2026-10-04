#!/usr/bin/env python3
"""
The C backend never renders a SimVariable or AIL repr as an identifier.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import archinfo

from angr.analyses.decompiler.structured_codegen.base import register_display_name, variable_display_name
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable


class TestCVariableNames(unittest.TestCase):
    def test_display_names(self):
        assert variable_display_name(SimStackVariable(-0x158, 1, base="bp", ident="is_31")) == "s_158"
        assert variable_display_name(SimStackVariable(8, 4, base="bp", ident="is_1")) == "arg_8"
        assert variable_display_name(SimRegisterVariable(16, 8, ident="ir_0")) == "reg_10"
        assert variable_display_name(SimMemoryVariable(0x401000, 4, ident="ig_0")) == "g_401000"
        assert variable_display_name(SimTemporaryVariable(3, 32)) == "tmp_3"
        arch = archinfo.ArchAMD64()
        assert register_display_name(arch, arch.registers["rsp"][0], 8) == "rsp"
        assert register_display_name(arch, 9999, 8) == "reg_270f"


if __name__ == "__main__":
    unittest.main()

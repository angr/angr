#!/usr/bin/env python3
"""
The C backend never renders a SimVariable or AIL repr as an identifier.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import archinfo

import angr
from angr.analyses import CFGFast, CompleteCallingConventionsAnalysis, Decompiler
from angr.analyses.decompiler.structured_codegen.base import register_display_name, variable_display_name
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.c_serialize import parse_codegen, serialize_codegen
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable
from tests.common import bin_location

_fp_dir = os.path.join(bin_location, "tests", "decompiler_fp")


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

    def test_reference_to_slot_before_its_first_write(self):
        # rsp before the first alloca is &slot, seen before any block writes slot: variable recovery created a
        # temporary 1-byte variable for the reference and dropped it from the unified variables
        proj = angr.Project(os.path.join(_fp_dir, "alloca_slot_amd64.o"), auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(proj.kb.functions["alloca_slot"], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "<0x" not in text, text
        assert len(re.findall(r"// \[bp-0x28\]", text)) == 1, text
        m = re.search(r"(\w+);  // \[bp-0x28\]", text)
        assert m is not None, text
        assert re.search(rf"rsp = .*&{m.group(1)}\b", text), text
        parsed = parse_codegen(serialize_codegen(dec.codegen), project=proj, kb=dec.kb, func=dec.func)
        assert parsed.text == text

    def test_default_local_names_are_unique(self):
        # sub_4051d0 declares a VLA, so Clinic names its variables a second time once the buffer exists; with
        # argument names of the default form, neither pass may give a local a name that is already in use
        proj = angr.Project(os.path.join(bin_location, "tests", "x86_64", "decompiler", "ffs"), auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True)
        proj.analyses[CompleteCallingConventionsAnalysis].prep()()
        func = cfg.functions[0x4051D0]
        assert func.prototype is not None
        proto = func.prototype.copy()
        proto.arg_names = tuple(f"v{i}" for i in range(len(proto.args)))
        func.set_prototype(None, proto, PrototypeSource.USER)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert isinstance(dec.codegen, CStructuredCodeGenerator) and dec.codegen.cfunc is not None
        text = dec.codegen.text
        assert text is not None
        assert re.search(r"uint8_t \w+\[.+\];\s*// alloca", text), text
        arg_names = [arg.name for arg in dec.codegen.cfunc.arg_list]
        assert arg_names == ["v0", "v1"], arg_names
        local_names = [var.name for var in dec.codegen.cfunc.unified_local_vars]
        assert len(local_names) == len(set(local_names)), local_names
        assert not set(arg_names) & set(local_names), sorted(set(arg_names) & set(local_names))


if __name__ == "__main__":
    unittest.main()

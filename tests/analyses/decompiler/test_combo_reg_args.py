#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
"""Tests for decompiling functions whose prototypes have by-value struct arguments passed in registers.

A by-value struct argument that is passed entirely in registers becomes a combo-register argument
(SimComboRegisterVariable); a struct argument with no known locations (empty or unknown struct
layout, e.g. std::forward_iterator_tag parsed from an Itanium-mangled name) must be treated as an
opaque variable instead. Both used to crash ssailification with `assert offset is not None` in
RewritingAnalysis._initial_abstract_state.
"""
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from collections import OrderedDict

import angr
from angr.calling_conventions import SimCCSystemVAMD64
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimStruct, SimTypeChar, SimTypeFunction, SimTypeInt, SimTypeLongLong, SimTypePointer

from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestComboRegArgs(unittest.TestCase):
    def _decompile_authenticate(self, proto: SimTypeFunction) -> str:
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True, data_references=True)

        func = cfg.functions["authenticate"]
        assert func is not None
        func.prototype = proto.with_arch(proj.arch)
        func.calling_convention = SimCCSystemVAMD64(proj.arch)
        func.prototype_libname = None
        func.prototype_source = PrototypeSource.USER

        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        return dec.codegen.text

    def test_two_register_combo_argument(self):
        # a 16-byte struct passed by value lands in two registers (rdi, rsi on SysV AMD64) and becomes a
        # combo-register argument
        pair = SimStruct(OrderedDict(a=SimTypeLongLong(), b=SimTypeLongLong()), name="pair_t", pack=False)
        proto = SimTypeFunction([pair], SimTypeInt(signed=True), arg_names=["p"])

        text = self._decompile_authenticate(proto)
        assert "pair_t p" in text
        assert "/* unsupported instruction */" not in text

    def test_empty_struct_argument(self):
        # an empty struct has no argument locations; it must be treated as an opaque variable instead of a
        # zero-register combo-register argument
        empty = SimStruct(OrderedDict(), name="empty_t", pack=False)
        char_ptr = SimTypePointer(SimTypeChar())
        proto = SimTypeFunction([empty, char_ptr, char_ptr], SimTypeInt(signed=True), arg_names=["e", "s", "t"])

        text = self._decompile_authenticate(proto)
        assert "authenticate" in text


if __name__ == "__main__":
    unittest.main()

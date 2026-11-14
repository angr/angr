#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

import archinfo

import angr
from angr import default_cc
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CExpression,
    CStructuredCodeGenerator,
)
from angr.sim_type import (
    PointerDisposition,
    SimCppClass,
    SimStruct,
    SimTypeBottom,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypePointer,
)
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestStructMemberAccess(unittest.TestCase):
    def test_struct_member_write(self):
        self._check_struct_member_write(None)

    def test_struct_member_write_in_pointer(self):
        # the callee is known to read the struct: the members are merged into one stack variable during SSA
        self._check_struct_member_write(PointerDisposition.IN)

    def _check_struct_member_write(self, disposition: PointerDisposition | None):
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
        if disposition is not None:
            foo_func.prototype.args[0].disposition = disposition

        dec = proj.analyses.Decompiler(main_func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text
        assert '.a = "123"' in text
        assert ".b.a = 2" in text
        assert ".b.b = 3" in text


class TestStructMemberSlotReuse(unittest.TestCase):
    def test_struct_member_read_before_overwrite(self):
        # gcc -O2 of: s.a = x; s.b = y; g(&s); old = s.a; s.a = y + 1; h(old); g(&s); return s.b;
        # the old s.a is reloaded into rdi before the slot is overwritten, so h() gets the old value
        f_addr, g_addr, h_addr = 0x401130, 0x401180, 0x401190
        code = bytes.fromhex(
            "55534889f34883c3014883ec184889e548893c244889ef4889742408e82f000000488b3c2448891c24e832000000"
            "4889efe81a000000488b4424084883c4185b5dc3662e0f1f8400000000000f1f4000"
            "488b074803470848894708c30f1f4000"  # g
            "48893d812e0000c3"  # h
        )
        proj = angr.load_shellcode(code, arch="AMD64", load_address=f_addr)
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[f_addr, g_addr, h_addr])
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        proj.kb.functions[g_addr].name = "g"
        proj.kb.functions[h_addr].name = "h"
        arch = proj.arch
        struct = SimStruct({"a": SimTypeLongLong(), "b": SimTypeLongLong()}, name="S").with_arch(arch)
        proj.kb.functions[g_addr].prototype = SimTypeFunction(
            [SimTypePointer(struct)], SimTypeLongLong()
        ).with_arch(arch)
        proj.kb.functions[h_addr].prototype = SimTypeFunction([SimTypeLongLong()], SimTypeBottom()).with_arch(arch)

        dec = proj.analyses.Decompiler(proj.kb.functions[f_addr], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text
        assert re.search(r"\b(v\d+)\.a = [^;]+;\s*h\(\1\.a\);", text) is None, text
        written = re.search(r"\b(v\d+)\.a = a0;", text)
        assert written is not None, text
        assert re.search(rf"\bh\({written.group(1)}\.a\);", text) is not None, text


class _MinimalCodegen(CStructuredCodeGenerator):
    """The real code generator with only the state ``_access`` reads.

    Constructing a full ``CStructuredCodeGenerator`` needs a decompilation; ``_access`` itself
    needs an architecture and the node-numbering counters, so this initialises exactly those
    and leaves the method under test untouched.
    """

    class _Project:  # pylint:disable=too-few-public-methods
        def __init__(self, arch):
            self.arch = arch

    def __init__(self, arch):  # pylint:disable=super-init-not-called
        self.project = self._Project(arch)
        self.reset_ident_counters()
        self._next_node_idx = 0
        self.cstyle_null_cmp = False

    def _access_constant_offset(self, *args, **kwargs):
        # A tripwire rather than a stub: if the walk ever descends by a constant offset the test
        # has taken a different path and would otherwise pass for the wrong reason.
        raise AssertionError("_access should not reach _access_constant_offset here")


class _TypedExpression(CExpression):
    """A leaf expression that only has to carry a type."""

    def __init__(self, ty, codegen):
        super().__init__(codegen=codegen)
        self._ty = ty

    @property
    def type(self):
        return self._ty

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield "x", self


class TestAccessOpaqueAggregate(unittest.TestCase):
    def test_access_through_pointer_to_member_less_class(self):
        # An opaque C++ class - one whose layout angr does not know - is built with no members
        # and a forced size, so its `offsets` is empty while its size is non-zero. Indexing
        # through a pointer to one used to select the greatest field offset not past the running
        # constant, which is `max()` over an empty sequence.
        #
        # The shape matters: two summed terms are needed for `_access` to enter its `while terms`
        # loop at all, because a lone expression becomes the kernel and the loop never runs. With
        # `p + i` the state on entry is a zero constant, a kernel stride of the class size and a
        # next stride of one, which is the state observed on a real binary that hit this.
        arch = archinfo.ArchX86()
        codegen = _MinimalCodegen(arch)
        opaque = SimCppClass(unique_name="Opaque", name="Opaque", members={}, size=32)
        assert not opaque.with_arch(arch).offsets

        pointer = _TypedExpression(SimTypePointer(opaque).with_arch(arch), codegen)
        index = _TypedExpression(SimTypeInt(signed=True).with_arch(arch), codegen)
        summed = CBinaryOp("Add", pointer, index, codegen=codegen)

        # bails out to pointer arithmetic instead of raising
        result = CStructuredCodeGenerator._access(codegen, summed, SimTypeInt(signed=True).with_arch(arch), False)
        assert isinstance(result, CExpression)


if __name__ == "__main__":
    unittest.main()

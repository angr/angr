#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
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
    SimTypeInt,
    SimTypePointer,
)
from tests.common import bin_location, print_decompilation_result

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
        foo_func.prototype.args[0].disposition = PointerDisposition.IN

        dec = proj.analyses.Decompiler(main_func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text
        assert '.a = "123"' in text
        assert ".b.a = 2" in text
        assert ".b.b = 3" in text


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

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Generic instantiations' shape types spelled as type literals (``go.shape.struct { ... }``)."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

from .test_go_decompiler import GoDecompilationTarget, go_binary

POINTER_STORE = "sync/atomic.(*Pointer[go.shape.struct { Cur uint64; Max uint64 }]).Store"
ONCE_VALUE = "sync.OnceValue[go.shape.interface { Error() string }]"


class TestShapeLiteralsGo127(GoDecompilationTarget):
    """DWARF types these stdlib instantiations' parameters with shape literals; the shapes render as the literals."""

    BINARY = go_binary("go1.27.1", "slices")
    FUNCS = (POINTER_STORE, ONCE_VALUE)

    def check_struct_shape_parameter(self):
        text = self.texts[POINTER_STORE]
        assert self.header(text) == (
            "func (x *sync/atomic.Pointer[go.shape.struct { Cur uint64; Max uint64 }]) "
            "Store(.dict *[16]uintptr, val *struct { Cur uint64; Max uint64 }) {"
        ), text
        assert "sync/atomic.StorePointer(x, val)\n" in text

    def check_interface_shape_in_func_type(self):
        text = self.texts[ONCE_VALUE]
        assert self.header(text) == (
            f"func {ONCE_VALUE}(.dict *[4]uintptr, f func() interface {{ Error() string }}) "
            "func() interface { Error() string } {"
        ), text

    def test_shape_literals(self):
        self.run_checks()


if __name__ == "__main__":
    unittest.main()

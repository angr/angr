#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.ailment.expression import Call, Const
from angr.analyses.decompiler.callsite_maker import CallSiteMaker
from angr.calling_conventions import SimCCSystemVAMD64
from angr.procedures.stubs.format_parser import FormatParser
from angr.sim_type import SimTypePointer

FMT = b"%d %s %5c %lld %hhu %f %lf %n %p"


class _Callee:
    def __init__(self, name, proto):
        self.name = name
        self._proto = proto

    def get_prototype(self, flavor=None):  # pylint:disable=unused-argument
        return self._proto


class TestFormatArgumentTypes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proj = angr.load_shellcode(b"\x00" * 0x100 + FMT + b"\x00", "AMD64")
        libc = angr.SIM_LIBRARIES["libc.so"][0]
        cls.protos = {name: libc.get_prototype(name).with_arch(cls.proj.arch) for name in ("scanf", "printf")}

    def _types(self, name):
        csm = CallSiteMaker.__new__(CallSiteMaker)
        csm.project = self.proj
        csm.flavor = None
        csm._resolve_register_argument = lambda *_, **__: None
        call = Call(1, Const(2, 0x2000, 64), args=[Const(3, 0x100, 64)])
        return csm._determine_variadic_arguments_for_format_strings(
            _Callee(name, self.protos[name]), SimCCSystemVAMD64(self.proj.arch), call
        )

    def test_scanf_takes_pointers(self):
        types = self._types("scanf")
        assert all(isinstance(t, SimTypePointer) for t in types), types
        assert [t.c_repr() for t in types] == [
            "int *",
            "char *",
            "char *",
            "long long *",
            "char *",
            "float *",
            "double *",
            "int *",
            "void* *",
        ], types
        assert all(t.size == 64 for t in types)

    def test_printf_is_unchanged(self):
        types = [t.c_repr() for t in self._types("printf")]
        assert types == [
            "int",
            "char *",
            "char",
            "long long",
            "char",
            "double",
            "double",
            "unsigned int *",
            "unsigned int *",
        ], types

    def _printf_types(self, fmt: bytes):
        csm = CallSiteMaker.__new__(CallSiteMaker)
        csm.project = self.proj
        types = csm._printf_argument_types(FormatParser(project=self.proj), fmt)
        return None if types is None else [t.c_repr() for t in types]

    def test_printf_star_width_and_precision_take_an_int(self):
        # libcurl's glob error message
        assert self._printf_types(b"%s in URL position %zu:\n%s\n%*s^") == [
            "char *",
            "unsigned long",
            "char *",
            "int",
            "char *",
        ]
        assert self._printf_types(b"%.*s|%-08.3f|%%|%+x") == ["int", "char *", "double", "unsigned int"]

    def test_printf_unknown_conversion_is_unresolved(self):
        assert self._printf_types(b"%d %ls") is None
        assert self._printf_types(b"no conversions %%") == []


if __name__ == "__main__":
    unittest.main()

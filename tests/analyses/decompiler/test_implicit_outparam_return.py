#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
"""Tests for decompiling a function whose result the calling convention passes back through memory.

Anything too wide for the return register comes back through a hidden pointer: the caller hands the
callee somewhere to put it and the callee leaves that address in the return register. ReturnMaker used
to have no case for that location, so it logged "Unsupported type of return expression" and left the
return statement with no expression at all -- a bare `return;` under a signature still declaring the
wide return type.

The fixtures are built from tests_src/decompiler/struct_return.c, which is also where these tests read
the prototypes from. make_vec3 there returns a 24-byte struct on x86-64 and a 12-byte one on x86, and
both conventions return those in memory.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr.analyses.decompiler import Decompiler
from angr.calling_conventions import SimFunctionArgument, SimReferenceArgument
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, parse_file
from tests.common import bin_location, print_decompilation_result

BINARIES = {
    "x86-64": os.path.join(bin_location, "tests", "x86_64", "decompiler", "struct_return.o"),
    "x86": os.path.join(bin_location, "tests", "i386", "decompiler", "struct_return.o"),
}
SOURCE = os.path.join(bin_location, "tests_src", "decompiler", "struct_return.c")

# `return *((int192_t *)idx);` -- a load of the returned value through the pointer, capturing the
# variable the pointer lives in so the test can check it is the one the body wrote the struct to
LOADED_RETURN = re.compile(r"return \*\(\([^)]+ \*\)(\w+)\);")


class TestImplicitOutparamReturn(unittest.TestCase):
    @staticmethod
    def _decompile(binary: str, name: str) -> tuple[SimFunctionArgument | None, str]:
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True, data_references=True)
        with open(SOURCE, encoding="utf-8") as fp:
            prototype = parse_file(fp.read(), arch=proj.arch)[0][name]
        assert isinstance(prototype, SimTypeFunction)

        func = cfg.functions[name]
        cc = proj.factory.cc()
        func.prototype = prototype
        func.calling_convention = cc
        func.prototype_libname = None
        func.prototype_source = PrototypeSource.USER

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert prototype.returnty is not None
        return cc.return_val(prototype.returnty, perspective_returned=True), dec.codegen.text

    @staticmethod
    def _return_statements(text: str) -> list[str]:
        return [line.strip() for line in text.splitlines() if line.strip().startswith("return")]

    def test_a_struct_returned_through_a_hidden_pointer_reaches_the_c(self):
        # x86 is not a duplicate of x86-64 here: cdecl passes the hidden pointer on the stack, so the
        # location the caller sees is not a register at all and only the callee's half of the ABI
        # gives ReturnMaker something it can render
        for arch, binary in BINARIES.items():
            with self.subTest(arch=arch):
                return_val, text = self._decompile(binary, "make_vec3")
                assert isinstance(return_val, SimReferenceArgument), "this one is supposed to return in memory"

                returns = self._return_statements(text)
                assert returns, text
                assert all(line != "return;" for line in returns), text

                # the value is loaded through the pointer, rather than the pointer being returned in
                # its place
                loaded = [LOADED_RETURN.fullmatch(line) for line in returns]
                assert all(match is not None for match in loaded), text

                # and it is a pointer the body wrote the struct through
                for match in loaded:
                    assert match is not None
                    assert re.search(rf"\*\(\([^)]+\*\){re.escape(match.group(1))}\) = ", text), text

    def test_a_return_value_in_a_register_is_unchanged(self):
        # asking the calling convention for the callee's half of the ABI must not disturb the ordinary
        # case, where the value is in the return register whichever half you ask about
        return_val, text = self._decompile(BINARIES["x86-64"], "scale")
        assert not isinstance(return_val, SimReferenceArgument), "this one returns in a register"

        returns = self._return_statements(text)
        assert returns, text
        assert all(line != "return;" for line in returns), text
        assert not any(LOADED_RETURN.fullmatch(line) for line in returns), text


if __name__ == "__main__":
    unittest.main()

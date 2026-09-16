from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

import angr
from angr.analyses.decompiler.known_patterns import STD_STRING_LENGTH, STD_VECTOR_INT_SIZE, KnownPattern
from angr.analyses.decompiler.known_patterns.context import LIBSTDCXX, MSVC, PatternContext
from angr.analyses.decompiler.known_patterns.dsl import PBinOp, PConst, PField, PLoad
from tests.common import bin_location

STL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl")
MSVC_X64 = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_stl_msvc_17_x64.exe")
MSVC_X86 = os.path.join(bin_location, "tests", "i386", "windows", "known_patterns_stl_msvc_17_x86.exe")


def _ctx(bits, runtime, platform, arch):
    return PatternContext(arch, bits, bits // 8, platform, runtime, runtime is not None)


def _vector_finish_offset(pat: KnownPattern | None) -> int:
    # top node is PBinOp(Sar/Shr, (Sub(Load(PField(v, off)), Load(PField(v, 0))), 2))
    assert pat is not None
    shift = pat.pattern
    assert isinstance(shift, PBinOp)
    diff = shift.operands[0]
    assert isinstance(diff, PBinOp)
    finish = diff.operands[0]
    assert isinstance(finish, PLoad)
    field = finish.addr
    assert isinstance(field, PField)
    return field.offset


class TestPatternContext(TestCase):
    def test_from_project_detects_arch_and_runtime(self):
        cx = PatternContext.from_project(angr.Project(STL_BIN, auto_load_libs=False))
        assert cx.arch_name == "AMD64" and cx.bits == 64 and cx.ptr_size == 8
        assert cx.platform == "linux" and cx.cxx_runtime == LIBSTDCXX and cx.is_cpp

        cx = PatternContext.from_project(angr.Project(MSVC_X64, auto_load_libs=False))
        assert cx.arch_name == "AMD64" and cx.platform == "windows" and cx.cxx_runtime == MSVC

        cx = PatternContext.from_project(angr.Project(MSVC_X86, auto_load_libs=False))
        assert cx.arch_name == "X86" and cx.bits == 32 and cx.ptr_size == 4
        assert cx.platform == "windows" and cx.cxx_runtime == MSVC

    def test_word_scaling(self):
        assert _ctx(64, LIBSTDCXX, "linux", "AMD64").word(1) == 8
        assert _ctx(32, MSVC, "windows", "X86").word(1) == 4
        assert _ctx(64, MSVC, "windows", "AMD64").word_size == 8

    def test_one_template_three_layouts(self):
        # std::string::length: libstdc++ +8/8, MSVC x64 +16/8, MSVC x86 +16/4
        expected = {
            _ctx(64, LIBSTDCXX, "linux", "AMD64"): (8, 8),
            _ctx(64, MSVC, "windows", "AMD64"): (16, 8),
            _ctx(32, MSVC, "windows", "X86"): (16, 4),
        }
        for cx, (off, size) in expected.items():
            pat = STD_STRING_LENGTH.instantiate(cx)
            assert pat is not None
            # the built pattern is a PLoad(PBinOp(Add,(PVVar, PConst(off))), size)
            load = pat.pattern
            assert isinstance(load, PLoad)
            assert load.size == size
            add = load.addr
            assert isinstance(add, PBinOp)
            const = add.operands[1]
            assert isinstance(const, PConst)
            assert const.value == off

    def test_vector_size_word_scaled(self):
        # 64-bit: _M_finish at +8; 32-bit: at +4
        p64 = STD_VECTOR_INT_SIZE.instantiate(_ctx(64, LIBSTDCXX, "linux", "AMD64"))
        p32 = STD_VECTOR_INT_SIZE.instantiate(_ctx(32, LIBSTDCXX, "linux", "X86"))
        finish64 = _vector_finish_offset(p64)
        finish32 = _vector_finish_offset(p32)
        assert (finish64, finish32) == (8, 4)


if __name__ == "__main__":
    unittest.main()

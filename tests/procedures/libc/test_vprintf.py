#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import unittest

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import angr
from angr import SIM_LIBRARIES, claripy
from angr.misc import ux

DST = 0x300000
FMT = 0x200000
FILE_PTR = 0x220000
RET_ADDR = 0x1000


class TestVprintf(unittest.TestCase):
    """
    angr does not model va_list, so the v*printf family outputs its format without %-substitution. Each test calls the
    procedure through the libc library with arguments in the AMD64 argument registers, so the glibc prototypes (whose
    va_list argument is an array type) lay out the arguments.
    """

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", arch="amd64")

    def _call(self, name, fmt, *args):
        state = self.proj.factory.blank_state()
        state.memory.store(FMT, fmt)
        fd_offset = io_file_data_for_arch(state.arch)["fd"]
        state.mem[FILE_PTR + fd_offset :].int = 2
        state.memory.store(DST, b"\xff" * 16)
        for reg, val in zip(("rdi", "rsi", "rdx", "rcx", "r8", "r9"), args):
            setattr(state.regs, reg, val)
        proc = SIM_LIBRARIES["libc.so.6"][0].get(name, self.proj.arch)
        succ = self.proj.factory.procedure_engine.process(state, procedure=proc, ret_to=RET_ADDR)
        assert len(succ.flat_successors) == 1
        st = succ.flat_successors[0]
        return st, st.solver.eval_one(st.regs.eax)

    def _load(self, state, size):
        return state.solver.eval_one(state.memory.load(DST, size), cast_to=bytes)

    def test_vprintf(self):
        st, ret = self._call("vprintf", b"hello\n\x00", FMT, 0)
        assert ret == 6
        assert st.posix.dumps(1) == b"hello\n"

    def test_vprintf_leaves_conversions_unsubstituted(self):
        st, ret = self._call("vprintf", b"n=%d\n\x00", FMT, 0)
        assert ret == 5
        assert st.posix.dumps(1) == b"n=%d\n"

    def test_conversions_warn_once(self):
        ux.once_set.discard("vprintf-unmodeled-vprintf")
        with self.assertLogs("angr.procedures.libc.vprintf", "WARNING") as logs:
            self._call("vprintf", b"%d\x00", FMT, 0)
            self._call("vprintf", b"%d\x00", FMT, 0)
        assert len(logs.records) == 1

    def test_vprintf_chk(self):
        st, ret = self._call("__vprintf_chk", b"hi\x00", 1, FMT, 0)
        assert ret == 2
        assert st.posix.dumps(1) == b"hi"

    def test_vfprintf(self):
        st, ret = self._call("vfprintf", b"err\x00", FILE_PTR, FMT, 0)
        assert ret == 3
        assert st.posix.dumps(2) == b"err"

    def test_vfprintf_chk(self):
        st, ret = self._call("__vfprintf_chk", b"err\x00", FILE_PTR, 1, FMT, 0)
        assert ret == 3
        assert st.posix.dumps(2) == b"err"

    def test_vsprintf(self):
        st, ret = self._call("vsprintf", b"a%sc\x00", DST, FMT, 0)
        assert ret == 4
        assert self._load(st, 6) == b"a%sc\x00\xff"

    def test_vsprintf_chk(self):
        st, ret = self._call("__vsprintf_chk", b"abc\x00", DST, 1, 64, FMT, 0)
        assert ret == 3
        assert self._load(st, 5) == b"abc\x00\xff"

    def test_vsnprintf_truncates_and_returns_the_full_length(self):
        st, ret = self._call("vsnprintf", b"abcdef\x00", DST, 4, FMT, 0)
        assert ret == 6
        assert self._load(st, 5) == b"abc\x00\xff"

    def test_vsnprintf_size_zero_writes_nothing(self):
        st, ret = self._call("vsnprintf", b"abc\x00", DST, 0, FMT, 0)
        assert ret == 3
        assert self._load(st, 1) == b"\xff"

    def test_vsnprintf_chk_uses_maxlen_not_slen(self):
        # __vsnprintf_chk(s, maxlen, flag, slen, fmt, ap)
        st, ret = self._call("__vsnprintf_chk", b"abcdef\x00", DST, 3, 1, 64, FMT, 0)
        assert ret == 6
        assert self._load(st, 4) == b"ab\x00\xff"

    def test_vsnprintf_symbolic_format_keeps_both_outcomes(self):
        # A format of symbolic length must not be pinned to one length: both the fitting and the truncated outcome stay
        # satisfiable.
        state = self.proj.factory.blank_state()
        fmt = claripy.BVS("fmt", 8 * 6)
        state.memory.store(FMT, claripy.Concat(fmt, claripy.BVV(0, 8)))
        state.regs.rdi, state.regs.rsi, state.regs.rdx, state.regs.rcx = DST, 4, FMT, 0
        proc = SIM_LIBRARIES["libc.so.6"][0].get("vsnprintf", self.proj.arch)
        st = self.proj.factory.procedure_engine.process(state, procedure=proc, ret_to=RET_ADDR).flat_successors[0]
        ret = st.regs.eax
        assert st.solver.satisfiable(extra_constraints=[ret == 2])
        assert st.solver.satisfiable(extra_constraints=[ret == 6])
        short = st.copy()
        short.add_constraints(ret == 2)
        assert short.solver.eval_one(short.memory.load(DST + 2, 1)) == 0
        long = st.copy()
        long.add_constraints(ret == 6)
        assert long.solver.eval_one(long.memory.load(DST + 3, 1)) == 0

    def test_vsprintf_symbolic_format(self):
        state = self.proj.factory.blank_state()
        c = claripy.BVS("c", 8)
        state.memory.store(FMT, claripy.Concat(claripy.BVV(b"a"), c, claripy.BVV(0, 8)))
        state.add_constraints(c != 0)
        state.regs.rdi, state.regs.rsi, state.regs.rdx = DST, FMT, 0
        proc = SIM_LIBRARIES["libc.so.6"][0].get("vsprintf", self.proj.arch)
        st = self.proj.factory.procedure_engine.process(state, procedure=proc, ret_to=RET_ADDR).flat_successors[0]
        assert st.solver.eval_one(st.regs.eax) == 2
        st.add_constraints(c == ord("z"))
        assert self._load(st, 3) == b"az\x00"


if __name__ == "__main__":
    unittest.main()

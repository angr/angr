#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import unittest

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import angr
from angr import SIM_LIBRARIES, claripy

BUF = 0x200000
DST = 0x300000
FILE_PTR = 0x220000
PTR_SLOTS = 0x230000
RET_ADDR = 0x1000


class TestLibcExtras(unittest.TestCase):
    """
    stpncpy, memrchr, rawmemchr, strchrnul, asprintf, getline and getdelim. Each test calls the procedure through
    the libc library with arguments in the AMD64 argument registers.
    """

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", arch="amd64")

    def _call(self, name, *args, state=None):
        if state is None:
            state = self.proj.factory.blank_state()
        for reg, val in zip(("rdi", "rsi", "rdx", "rcx", "r8", "r9"), args):
            setattr(state.regs, reg, val)
        proc = SIM_LIBRARIES["libc.so.6"][0].get(name, self.proj.arch)
        assert not proc.is_stub, f"{name} is not implemented"
        succ = self.proj.factory.procedure_engine.process(state, procedure=proc, ret_to=RET_ADDR)
        assert len(succ.flat_successors) == 1
        return succ.flat_successors[0]

    @staticmethod
    def _ret(state, bits=64):
        ret = state.regs.rax[bits - 1 : 0]
        assert state.solver.unique(ret)
        return state.solver.eval(ret)

    @staticmethod
    def _bytes(state, addr, size):
        return state.solver.eval(state.memory.load(addr, size), cast_to=bytes)

    def _load_ptr(self, state, addr):
        return state.solver.eval(state.memory.load(addr, 8, endness=self.proj.arch.memory_endness))

    #
    # stpncpy
    #

    def test_stpncpy_pads_and_returns_nul_ptr(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"hi\x00")
        state.memory.store(DST, b"XXXXXXXXX")
        st = self._call("stpncpy", DST, BUF, 8, state=state)
        assert self._bytes(st, DST, 9) == b"hi" + b"\x00" * 6 + b"X"
        assert self._ret(st) == DST + 2

    def test_stpncpy_pads_large_window(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"hi\x00")
        state.memory.store(DST, b"Z" * 101)
        st = self._call("stpncpy", DST, BUF, 100, state=state)
        assert self._bytes(st, DST, 101) == b"hi" + b"\x00" * 98 + b"Z"
        assert self._ret(st) == DST + 2

    def test_stpncpy_truncates_and_returns_dst_plus_n(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"hello\x00")
        state.memory.store(DST, b"XXXX")
        st = self._call("stpncpy", DST, BUF, 3, state=state)
        assert self._bytes(st, DST, 4) == b"helX"
        assert self._ret(st) == DST + 3

    #
    # memrchr / rawmemchr / strchrnul
    #

    def test_memrchr_returns_last_match(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"AXcX")
        st = self._call("memrchr", BUF, ord("X"), 4, state=state)
        assert self._ret(st) == BUF + 3

    def test_memrchr_ignores_bytes_past_n(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"AXcX")
        st = self._call("memrchr", BUF, ord("X"), 3, state=state)
        assert self._ret(st) == BUF + 1

    def test_memrchr_not_found_and_zero_length(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"abcd")
        assert self._ret(self._call("memrchr", BUF, ord("X"), 4, state=state.copy())) == 0
        assert self._ret(self._call("memrchr", BUF, ord("a"), 0, state=state.copy())) == 0

    def test_memrchr_symbolic_byte(self):
        state = self.proj.factory.blank_state()
        sym = claripy.BVS("b", 8)
        state.memory.store(BUF, b"AXc")
        state.memory.store(BUF + 3, sym)
        state.solver.add(sym == ord("X"))
        st = self._call("memrchr", BUF, ord("X"), 4, state=state)
        assert self._ret(st) == BUF + 3

    def test_rawmemchr(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"ABXCD")
        st = self._call("rawmemchr", BUF, ord("X"), state=state)
        assert self._ret(st) == BUF + 2

    def test_rawmemchr_far_match(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"A" * 100 + b"X\x00")
        st = self._call("rawmemchr", BUF, ord("X"), state=state)
        assert self._ret(st) == BUF + 100

    def test_rawmemchr_nul_finds_end_of_string(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"A" * 100 + b"\x00")
        st = self._call("rawmemchr", BUF, 0, state=state)
        assert self._ret(st) == BUF + 100

    def test_strchrnul_found(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"abXd\x00")
        st = self._call("strchrnul", BUF, ord("X"), state=state)
        assert self._ret(st) == BUF + 2

    def test_strchrnul_not_found_returns_nul_ptr(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"ab\x00")
        st = self._call("strchrnul", BUF, ord("X"), state=state)
        # strchr would return NULL here; strchrnul points at the terminator
        assert self._ret(st) == BUF + 2

    def test_strchrnul_symbolic_terminator(self):
        # "a\0Xd": the 'X' after the terminator is not in the string
        state = self.proj.factory.blank_state()
        sym = claripy.BVS("s", 4 * 8)
        state.memory.store(BUF, sym)
        state.memory.store(BUF + 4, b"\x00")
        st = self._call("strchrnul", BUF, ord("X"), state=state)
        assert st.solver.satisfiable(extra_constraints=[sym == claripy.BVV(b"a\x00Xd")])
        assert st.solver.eval_one(st.regs.rax, extra_constraints=[sym == claripy.BVV(b"a\x00Xd")]) == BUF + 1

    #
    # asprintf
    #

    def test_asprintf(self):
        state = self.proj.factory.blank_state()
        state.memory.store(BUF, b"n=%d\x00")
        st = self._call("asprintf", PTR_SLOTS, BUF, 42, state=state)
        assert self._ret(st, bits=32) == 4
        buf = self._load_ptr(st, PTR_SLOTS)
        assert buf != 0
        assert self._bytes(st, buf, 5) == b"n=42\x00"

    #
    # getline / getdelim
    #

    def _stdin_state(self, content):
        stdin = angr.SimFileStream(name="stdin", content=content, has_end=True)
        state = self.proj.factory.blank_state(stdin=stdin)
        fd_offset = io_file_data_for_arch(state.arch)["fd"]
        state.mem[FILE_PTR + fd_offset :].int = 0
        # *lineptr = NULL, *n = 0: let the procedure allocate the buffer
        state.memory.store(PTR_SLOTS, claripy.BVV(0, 128))
        return state

    def test_getline(self):
        state = self._stdin_state(b"ab\ncd\n")
        st = self._call("getline", PTR_SLOTS, PTR_SLOTS + 8, FILE_PTR, state=state)
        assert self._ret(st) == 3
        line = self._load_ptr(st, PTR_SLOTS)
        assert self._bytes(st, line, 4) == b"ab\n\x00"

    def test_getdelim(self):
        state = self._stdin_state(b"ab;cd")
        st = self._call("getdelim", PTR_SLOTS, PTR_SLOTS + 8, ord(";"), FILE_PTR, state=state)
        assert self._ret(st) == 3
        line = self._load_ptr(st, PTR_SLOTS)
        assert self._bytes(st, line, 4) == b"ab;\x00"

    def test_getline_symbolic_input(self):
        state = self._stdin_state(claripy.BVS("line", 8 * 8))
        st = self._call("getline", PTR_SLOTS, PTR_SLOTS + 8, FILE_PTR, state=state)
        ret = st.regs.rax
        line = self._load_ptr(st, PTR_SLOTS)
        assert line != 0
        # the buffer holds the line plus its NUL terminator
        n = st.memory.load(PTR_SLOTS + 8, 8, endness=self.proj.arch.memory_endness)
        assert st.solver.is_true(n == ret + 1)
        assert st.solver.satisfiable(extra_constraints=[st.memory.load(line, 2) == b"ab"])

    def test_getline_caller_buffer(self):
        state = self._stdin_state(b"ab\ncd\n")
        old_buf = 0x240000
        state.memory.store(old_buf, b"Q" * 16)
        state.memory.store(PTR_SLOTS, claripy.BVV(old_buf, 64), endness=self.proj.arch.memory_endness)
        state.memory.store(PTR_SLOTS + 8, claripy.BVV(16, 64), endness=self.proj.arch.memory_endness)
        st = self._call("getline", PTR_SLOTS, PTR_SLOTS + 8, FILE_PTR, state=state)
        assert self._ret(st) == 3
        line = self._load_ptr(st, PTR_SLOTS)
        # the caller's buffer is big enough, so it is reused as is
        assert line == old_buf
        assert self._bytes(st, line, 4) == b"ab\n\x00"
        assert self._bytes(st, line + 4, 12) == b"Q" * 12
        assert self._load_ptr(st, PTR_SLOTS + 8) == 16

    def test_getline_grows_small_caller_buffer(self):
        state = self._stdin_state(b"abcdef\n")
        old_buf = 0x240000
        state.memory.store(old_buf, b"QQ")
        state.memory.store(PTR_SLOTS, claripy.BVV(old_buf, 64), endness=self.proj.arch.memory_endness)
        state.memory.store(PTR_SLOTS + 8, claripy.BVV(2, 64), endness=self.proj.arch.memory_endness)
        st = self._call("getline", PTR_SLOTS, PTR_SLOTS + 8, FILE_PTR, state=state)
        assert self._ret(st) == 7
        line = self._load_ptr(st, PTR_SLOTS)
        assert line != old_buf
        assert self._bytes(st, line, 8) == b"abcdef\n\x00"
        # *n is the capacity of the grown buffer, not the line length
        assert self._load_ptr(st, PTR_SLOTS + 8) >= 8

    def test_getline_symbolic_long_line(self):
        # with a symbolic input length, the allocation must not pin the line length
        size = claripy.BVS("size", 64)
        stdin = angr.SimFileStream(name="stdin", content=claripy.BVS("line", 200 * 8), size=size, has_end=True)
        state = self.proj.factory.blank_state(stdin=stdin)
        state.solver.add(claripy.ULE(size, 200))
        fd_offset = io_file_data_for_arch(state.arch)["fd"]
        state.mem[FILE_PTR + fd_offset :].int = 0
        state.memory.store(PTR_SLOTS, claripy.BVV(0, 128))
        st = self._call("getline", PTR_SLOTS, PTR_SLOTS + 8, FILE_PTR, state=state)
        assert st.solver.satisfiable(extra_constraints=[st.regs.rax == 200])

    def test_getline_symbolic_reuses_large_caller_buffer(self):
        state = self._stdin_state(claripy.BVS("line", 8 * 8))
        old_buf = 0x240000
        state.memory.store(PTR_SLOTS, claripy.BVV(old_buf, 64), endness=self.proj.arch.memory_endness)
        state.memory.store(PTR_SLOTS + 8, claripy.BVV(2048, 64), endness=self.proj.arch.memory_endness)
        st = self._call("getline", PTR_SLOTS, PTR_SLOTS + 8, FILE_PTR, state=state)
        assert self._load_ptr(st, PTR_SLOTS) == old_buf
        assert self._load_ptr(st, PTR_SLOTS + 8) == 2048

    def test_getdelim_compares_delimiter_as_unsigned_char(self):
        # getdelim(..., -1, ...) stops at byte 0xff, as glibc compares against (unsigned char)delim
        state = self._stdin_state(b"ab\xffcd")
        st = self._call("getdelim", PTR_SLOTS, PTR_SLOTS + 8, 0xFFFFFFFFFFFFFFFF, FILE_PTR, state=state)
        assert self._ret(st) == 3
        line = self._load_ptr(st, PTR_SLOTS)
        assert self._bytes(st, line, 4) == b"ab\xff\x00"

    def test_getdelim_both_names_hooked(self):
        # The public name is getdelim; glibc also exports __getdelim.
        libc = SIM_LIBRARIES["libc.so.6"][0]
        assert libc.has_implementation("getdelim")
        assert libc.has_implementation("__getdelim")


if __name__ == "__main__":
    unittest.main()

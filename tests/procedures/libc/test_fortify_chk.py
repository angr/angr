#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.procedures.libc"  # pylint:disable=redefined-builtin

import unittest

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import angr
from angr import SIM_LIBRARIES
from angr.sim_type import SimTypePointer

DST = 0x300000
SRC = 0x200000
FMT = 0x210000
FILE_PTR = 0x220000
RET_ADDR = 0x1000

# The __fprintf_chk and __sprintf_chk prototypes come from angr-data; releases before the fix give __sprintf_chk only
# two arguments.
_SPRINTF_CHK_PROTO = SIM_LIBRARIES["libc.so.6"][0].get_prototype("__sprintf_chk")
HAS_FIXED_PROTOTYPES = _SPRINTF_CHK_PROTO is not None and len(_SPRINTF_CHK_PROTO.args) == 4


class TestFortifyChk(unittest.TestCase):
    """
    The _FORTIFY_SOURCE variants (__*_chk) take extra flag/size arguments ahead of or after the ones of the base
    function. Each test calls the procedure through the libc library with arguments in the AMD64 argument registers.
    __sprintf_chk and __fprintf_chk get their argument layout from the glibc prototype in angr-data; the others have no
    prototype there and take it from run()'s signature.
    """

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90", arch="amd64")

    def _call(self, name, *args, state=None):
        if state is None:
            state = self.proj.factory.blank_state()
        for reg, val in zip(("rdi", "rsi", "rdx", "rcx", "r8", "r9"), args):
            setattr(state.regs, reg, val)
        proc = SIM_LIBRARIES["libc.so.6"][0].get(name, self.proj.arch)
        succ = self.proj.factory.procedure_engine.process(state, procedure=proc, ret_to=RET_ADDR)
        assert len(succ.flat_successors) == 1
        return succ.flat_successors[0]

    def _load_str(self, state, addr, size):
        return state.solver.eval(state.memory.load(addr, size), cast_to=bytes)

    @staticmethod
    def _prototype(name):
        return SIM_LIBRARIES["libc.so.6"][0].get_prototype(name)

    @unittest.skipUnless(HAS_FIXED_PROTOTYPES, "the installed angr-data has the old __sprintf_chk prototype")
    def test_fortify_prototypes(self):
        # __fprintf_chk(FILE *stream, int flag, const char *fmt, ...)
        fprintf_chk = self._prototype("__fprintf_chk")
        assert isinstance(fprintf_chk.args[0], SimTypePointer)
        assert list(fprintf_chk.arg_names[:3]) == ["STREAM", "flag", "TEMPLATE"]
        # __sprintf_chk(char *s, int flag, size_t slen, const char *fmt, ...)
        sprintf_chk = self._prototype("__sprintf_chk")
        assert list(sprintf_chk.arg_names[:4]) == ["S", "flag", "slen", "TEMPLATE"]

    @unittest.skipUnless(HAS_FIXED_PROTOTYPES, "the installed angr-data has the old __sprintf_chk prototype")
    def test_sprintf_chk(self):
        state = self.proj.factory.blank_state()
        state.memory.store(FMT, b"%d-%d\x00")
        # __sprintf_chk(s, flag, slen, fmt, ...)
        st = self._call("__sprintf_chk", DST, 1, 64, FMT, 42, 7, state=state)
        assert self._load_str(st, DST, 5) == b"42-7\x00"
        assert st.solver.eval(st.regs.rax) == 4

    def test_fprintf_chk(self):
        state = self.proj.factory.blank_state()
        state.memory.store(FMT, b"%d\x00")
        fd_offset = io_file_data_for_arch(state.arch)["fd"]
        state.mem[FILE_PTR + fd_offset :].int = 1
        # __fprintf_chk(fp, flag, fmt, ...)
        st = self._call("__fprintf_chk", FILE_PTR, 1, FMT, 42, state=state)
        assert st.posix.dumps(1) == b"42"
        assert st.solver.eval(st.regs.rax) == 2

    def test_strcpy_chk(self):
        state = self.proj.factory.blank_state()
        state.memory.store(SRC, b"hello\x00")
        st = self._call("__strcpy_chk", DST, SRC, 64, state=state)
        assert self._load_str(st, DST, 6) == b"hello\x00"
        assert st.solver.eval(st.regs.rax) == DST

    def test_stpcpy_chk(self):
        state = self.proj.factory.blank_state()
        state.memory.store(SRC, b"hello\x00")
        st = self._call("__stpcpy_chk", DST, SRC, 64, state=state)
        assert self._load_str(st, DST, 6) == b"hello\x00"
        # stpcpy returns a pointer to the terminating NUL
        assert st.solver.eval(st.regs.rax) == DST + 5

    def test_strcat_chk(self):
        state = self.proj.factory.blank_state()
        state.memory.store(DST, b"ab\x00")
        state.memory.store(SRC, b"cd\x00")
        st = self._call("__strcat_chk", DST, SRC, 64, state=state)
        assert self._load_str(st, DST, 5) == b"abcd\x00"

    def test_strncpy_chk(self):
        state = self.proj.factory.blank_state()
        state.memory.store(DST, b"XXXXXX")
        state.memory.store(SRC, b"hello\x00")
        st = self._call("__strncpy_chk", DST, SRC, 3, 64, state=state)
        assert self._load_str(st, DST, 6) == b"helXXX"

    def test_strncat_chk(self):
        state = self.proj.factory.blank_state()
        state.memory.store(DST, b"ab\x00")
        state.memory.store(SRC, b"cdef\x00")
        st = self._call("__strncat_chk", DST, SRC, 2, 64, state=state)
        assert self._load_str(st, DST, 5) == b"abcd\x00"


if __name__ == "__main__":
    unittest.main()

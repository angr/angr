#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import functools
import struct
import unittest

from angr.analyses.unpacker.emulation.icicle_environment import patched_processors
from angr.rustylib import winemu
from angr.rustylib.winemu import WinVm

from . import icicle_op_vectors as vectors
from .icicle_op_vectors import CODE, DATA, DSIZE

GPR64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
GPR32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
State = tuple[list[int], int, list[int], bytes]


@functools.cache
def _vm(is_64bit: bool, jit: bool) -> WinVm:
    vm = WinVm(is_64bit, patched_processors(), jit)
    # compile on first use, so that the JIT's path to the helpers is the one tested
    vm.jit_threshold = 0
    vm.mem_map(CODE, 0x1000, 7)
    vm.mem_map(DATA, DSIZE, 3)
    return vm


def _execute(vm: WinVm, code: bytes, state: State) -> State:
    names = GPR64 if vm.is_64bit else GPR32
    gpr, flags, xmm, mem = state
    vm.mem_write(CODE, code + b"\xcc")
    vm.mem_write(DATA, mem)
    for name, value in zip(names, gpr):
        vm.reg_write(name, value)
    for i, value in enumerate(xmm):
        vm.reg_write_bytes(f"xmm{i}", value.to_bytes(16, "little"))
    vm.reg_write("mxcsr", 0x1F80)
    vm.reg_write("eflags", flags | 2)
    vm.pc = CODE
    kind, fault, _ = vm.run(100)
    assert (kind, fault, vm.pc) == (winemu.EXIT_EXCEPTION, winemu.FAULT_SYSCALL, CODE + len(code)), code.hex()
    return (
        [vm.reg_read(name) for name in names],
        vm.reg_read("eflags"),
        [int.from_bytes(vm.reg_read_bytes(f"xmm{i}"), "little") for i in range(len(xmm))],
        vm.mem_read(DATA, DSIZE),
    )



class TestOpVectors(unittest.TestCase):
    """
    The interpreter and the JIT against results recorded from a CPU.
    """

    def _check(self, entries: tuple[tuple, ...]) -> None:
        for is_64bit, code, kind, expected, *mask in entries:
            states = [vectors.make_state(f"{code}/{trial}", bool(is_64bit), kind) for trial in range(4)]
            for jit in (False, True):
                vm = _vm(bool(is_64bit), jit)
                results = [_execute(vm, bytes.fromhex(code), state) for state in states]
                assert vectors.digest(results, mask[0] if mask else 0x8D5) == expected, (code, is_64bit, jit)

    def test_sse2(self):
        self._check(vectors.SSE2)








class TestSse(unittest.TestCase):
    def test_conversion_out_of_range(self):
        # cvttsd2si eax, xmm1 / cvtsd2si / cvttss2si of 1e10, NaN and -1e10 give the integer indefinite
        for jit in (False, True):
            for value in (1e10, float("nan"), -1e10):
                vm = _vm(False, jit)
                for code, raw in (("f20f2cc1", struct.pack("<d", value)), ("f20f2dc1", struct.pack("<d", value)),
                                  ("f30f2cc1", struct.pack("<f", value))):  # fmt: skip
                    vm.reg_write_bytes("xmm1", raw.ljust(16, b"\0"))
                    vm.mem_write(CODE, bytes.fromhex(code) + b"\xcc")
                    vm.pc = CODE
                    vm.run(10)
                    assert vm.reg_read("eax") == 0x80000000, (code, value, jit)
        # cvtsd2si rounds to nearest even: 2.5 -> 2, 3.5 -> 4
        for value, expected in ((2.5, 2), (3.5, 4), (-2.5, 0xFFFFFFFE)):
            vm = _vm(False, False)
            vm.reg_write_bytes("xmm1", struct.pack("<d", value).ljust(16, b"\0"))
            vm.mem_write(CODE, bytes.fromhex("f20f2dc1cc"))
            vm.pc = CODE
            vm.run(10)
            assert vm.reg_read("eax") == expected






if __name__ == "__main__":
    unittest.main()

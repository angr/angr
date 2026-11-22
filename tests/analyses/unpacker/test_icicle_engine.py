#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import os
import struct
import unittest
from unittest import mock

from angr.analyses.unpacker.emulation import StopReason
from angr.analyses.unpacker.emulation.icicle_environment import IcicleWindowsEmulator, patched_processors
from angr.rustylib import winemu
from angr.rustylib.winemu import WinVm

from . import test_emulation
from .pe_builder import IMAGE_BASE
from .test_emulation import CODE_RVA, emulator

CODE = 0x400000


def _vm(is_64bit: bool = False) -> WinVm:
    vm = WinVm(is_64bit, patched_processors())
    vm.mem_map(CODE, 0x2000, 7)
    vm.mem_map(0x500000, 0x1000, 3)
    vm.reg_write("rsp" if is_64bit else "esp", 0x500F00)
    return vm


def _run(vm: WinVm, code: bytes) -> tuple[int, int, int]:
    vm.mem_write(CODE, code + b"\xcc")
    vm.pc = CODE
    return vm.run(1000)


class TestWinVm(unittest.TestCase):
    def test_store_into_executed_code(self):
        # call a nop sled, then stosd and push over it: the instructions finish once, with their side effects
        vm = _vm()
        vm.mem_write(CODE + 0x100, b"\x90" * 16 + b"\xc3")
        code = bytes.fromhex("e8fb000000 bf00014000 b844332211 ab bc10014000 6888776655")
        assert _run(vm, code) == (winemu.EXIT_EXCEPTION, winemu.FAULT_SYSCALL, 3)
        assert vm.mem_read(CODE + 0x100, 16) == bytes.fromhex("44332211") + b"\x90" * 8 + bytes.fromhex("88776655")
        assert vm.reg_read("edi") == CODE + 0x104
        assert vm.reg_read("esp") == CODE + 0x10C
        assert vm.smc_count == 1

    def test_redundant_rex_prefix(self):
        # es: rex.w rex.w mov [rax], rdx; SLEIGH rejects the first REX, which the CPU ignores
        vm = _vm(True)
        vm.reg_write("rax", 0x500100)
        vm.reg_write("rdx", 0x1122334455667788)
        assert _run(vm, bytes.fromhex("26 48 48 89 10"))[1] == winemu.FAULT_SYSCALL
        assert vm.mem_read(0x500100, 8) == struct.pack("<Q", 0x1122334455667788)
        assert vm.fixups == 1

    def test_flags(self):
        vm = _vm()
        # mov eax, 0x80000001; shr eax, 1 (imm8 form): OF is the old sign; pushfd keeps bit 1 set
        _run(vm, bytes.fromhex("b801000080 c1e801 9c"))
        flags = struct.unpack("<I", vm.mem_read(vm.reg_read("esp"), 4))[0]
        assert flags & 0x803 == 0x803
        # mov al, 0x0f; add al, 1: auxiliary carry
        _run(vm, bytes.fromhex("b00f 0401 9c"))
        assert struct.unpack("<I", vm.mem_read(vm.reg_read("esp"), 4))[0] & 0x10

    def test_cpuid_and_privileged(self):
        vm = _vm()
        assert _run(vm, bytes.fromhex("31c0 0fa2"))[1] == winemu.FAULT_SYSCALL
        assert struct.pack("<III", vm.reg_read("ebx"), vm.reg_read("edx"), vm.reg_read("ecx")) == b"GenuineIntel"
        assert _run(vm, bytes.fromhex("f4"))[0] == winemu.EXIT_PRIVILEGED


@mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": "rust"})
class TestIcicleExceptions(test_emulation.TestExceptions):
    """
    The exception tests of the Unicorn engine, on Icicle.
    """

    def test_engine(self):
        assert isinstance(emulator(b"\xc3"), IcicleWindowsEmulator)

    def test_returns(self):
        emu = emulator(b"\xb8\x07\x00\x00\x00\xc3")
        emu.start()
        assert emu.run(max_blocks=1000).reason is StopReason.RETURNED
        assert emu.reg("eax") == 7
        assert emu.read(IMAGE_BASE + CODE_RVA, 1) == b"\xb8"


if __name__ == "__main__":
    unittest.main()

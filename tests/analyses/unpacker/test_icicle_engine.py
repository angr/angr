#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import os
import struct
import unittest
from unittest import mock

from angr.analyses.unpacker.emulation import StopReason
from angr.analyses.unpacker.emulation.apis import API_HANDLERS
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

    def test_x64_zero_extension_and_shift_flags(self):
        vm = _vm(True)
        vm.mem_write(0x500100, struct.pack("<I", 0x11223344))
        vm.reg_write("rax", 0x500100)
        vm.reg_write("r10", 0xF6620AA00)
        # xchg [rax], r10d clears the upper half of r10
        _run(vm, bytes.fromhex("448710"))
        assert vm.reg_read("r10") == 0x11223344
        # shr di, cl with cl = 0 keeps AF
        vm.reg_write("rcx", 0)
        vm.reg_write("eflags", 0x12)
        _run(vm, bytes.fromhex("66d3ef 9c"))
        assert struct.unpack("<Q", vm.mem_read(vm.reg_read("rsp"), 8))[0] & 0x10

    def test_precise_faults(self):
        # a fault leaves the registers as they were before the instruction
        for code in ("ab", "50", "a5", "f3ab", "60", "8f00", "e800000000"):
            vm = _vm()
            regs = {"eax": 0x600000, "ecx": 2, "edi": 0x600000, "esi": 0x500100, "esp": 0x600010}
            if code == "8f00":
                regs["esp"] = 0x500100
            for name, value in regs.items():
                vm.reg_write(name, value)
            assert _run(vm, bytes.fromhex(code))[:2] == (winemu.EXIT_EXCEPTION, winemu.FAULT_WRITE), code
            assert vm.pc == CODE
            assert {name: vm.reg_read(name) for name in regs} == regs, code

    def test_divide_overflow(self):
        vm = _vm()
        vm.reg_write("eax", 0x80000000)
        vm.reg_write("edx", 0xFFFFFFFF)
        vm.reg_write("ecx", 0xFFFFFFFF)
        # idiv ecx: the quotient 2**31 does not fit, so a divide error before any register changes
        assert _run(vm, bytes.fromhex("f7f9"))[:2] == (winemu.EXIT_EXCEPTION, winemu.FAULT_DIVIDE)
        assert vm.pc == CODE
        assert vm.reg_read("eax") == 0x80000000

    def test_16bit_addressing(self):
        # 0x67-prefixed operands use a 16-bit offset (from the FS base here); the stack keeps its 32-bit esp
        vm = _vm()
        vm.reg_write("fs_base", 0x500000)
        vm.mem_write(0x500030, struct.pack("<I", 0x11223344))
        # mov ebx, fs:[0x30]; push dword fs:[0x30]; pop dword fs:[0x40]
        _run(vm, bytes.fromhex("64678b1e3000 6764ff363000 64678f064000"))
        assert vm.reg_read("ebx") == 0x11223344
        assert vm.reg_read("esp") == 0x500F00
        assert vm.mem_read(0x500040, 4) == struct.pack("<I", 0x11223344)

    def test_descriptor_instructions(self):
        vm = _vm()
        # lsl / lar on the user data selector, then on the null selector, which leaves the destination alone
        vm.reg_write("edi", 0x23)
        _run(vm, bytes.fromhex("0f03df 0f02c7"))
        assert (vm.reg_read("ebx"), vm.reg_read("eax"), vm.reg_read("ZF")) == (0xFFFFFFFF, 0x00CFF300, 1)
        vm.reg_write("edi", 0)
        _run(vm, bytes.fromhex("0f03df"))
        assert (vm.reg_read("ebx"), vm.reg_read("ZF")) == (0xFFFFFFFF, 0)
        # verr / verw: code is readable, not writable
        for code, selector, zf in (("0f00e7", 0x1B, 1), ("0f00ef", 0x1B, 0), ("0f00ef", 0x3B, 1), ("0f00e7", 0x8, 0)):
            vm.reg_write("edi", selector)
            _run(vm, bytes.fromhex(code))
            assert vm.reg_read("ZF") == zf, (code, selector)
        # xgetbv: x87 and SSE state enabled
        vm.reg_write("ecx", 0)
        _run(vm, bytes.fromhex("0f01d0"))
        assert (vm.reg_read("eax"), vm.reg_read("edx")) == (3, 0)

    def test_user_ops_and_wide_registers(self):
        vm = _vm()
        handled = dict(vm.user_ops())
        assert handled["segment"] == "helper" and handled["cpuid"] == "lifter"
        # an op nobody implements raises "unimplemented" (0x100a) when reached
        assert handled["xsavec"] == ""
        value = bytes(range(16))
        vm.reg_write_bytes("xmm3", value)
        # movdqa xmm1, xmm3
        _run(vm, bytes.fromhex("660f6fcb"))
        assert vm.reg_read_bytes("xmm1") == value

    def test_privileged_and_absent_instructions(self):
        # wrmsr, invlpg [eax], mwait: privileged; vmcall, vmxon [eax], vmmcall, xbegin, xtest: undefined opcodes
        for code in ("0f30", "0f0138", "0f01c9"):
            vm = _vm()
            vm.reg_write("eax", 0x500100)
            assert _run(vm, bytes.fromhex(code))[0] == winemu.EXIT_PRIVILEGED, code
            assert vm.pc == CODE
        for code in ("0f01c1", "f30fc730", "0f01d9", "c7f800000000", "0f01d6"):
            vm = _vm()
            vm.reg_write("eax", 0x500100)
            assert _run(vm, bytes.fromhex(code))[:2] == (winemu.EXIT_EXCEPTION, winemu.FAULT_INVALID), code
            assert vm.pc == CODE
        # an HLE prefix is a hint: xacquire lock inc dword [eax]
        vm = _vm()
        vm.reg_write("eax", 0x500100)
        assert _run(vm, bytes.fromhex("f2f0ff00"))[1] == winemu.FAULT_SYSCALL
        assert vm.mem_read(0x500100, 4) == struct.pack("<I", 1)

    def test_time_stamp_counter(self):
        # rdtsc; mov ebx, eax; mov ecx, edx; rdtsc
        code = bytes.fromhex("0f31 89c3 89d1 0f31")
        runs = []
        for _ in range(2):
            vm = _vm()
            vm.clock = 1000
            _run(vm, code)
            first = vm.reg_read("ecx") << 32 | vm.reg_read("ebx")
            second = vm.reg_read("edx") << 32 | vm.reg_read("eax")
            # 250 ms later on the emulated clock (a Sleep), rdtscp
            vm.clock = 1250
            _run(vm, bytes.fromhex("0f01f9"))
            third = vm.reg_read("edx") << 32 | vm.reg_read("eax")
            runs.append((first, second, third))
        # the same in every run; some cycles between two reads; the clock's delta at 3.6 GHz across the sleep
        assert runs[0] == runs[1]
        first, second, third = runs[0]
        assert first // 3_600_000 == 1000 and 0 < second - first < 100
        assert 0 <= third - second - 250 * 3_600_000 < 100
        assert vm.reg_read("ecx") == 0

    def test_user_mode_interrupt_flag(self):
        # push 0; popfd; pushfd; pop eax: IF stays set, as for any user-mode thread
        vm = _vm()
        vm.reg_write("if", 1)
        assert _run(vm, bytes.fromhex("6a00 9d 9c 58"))[1] == winemu.FAULT_SYSCALL
        assert vm.reg_read("eax") == 0x202

    def test_io_privileged_instructions(self):
        # cli, sti, in, out and their string forms need I/O privilege: they fault and change nothing
        for is_64bit in (False, True):
            for code in ("fa", "fb", "ec", "ed", "e410", "e510", "ee", "ef", "e610", "e710", "6c", "6d", "6e", "6f"):
                for prefix in ("", "f3"):
                    if prefix and code[0] != "6":
                        continue
                    vm = _vm(is_64bit)
                    vm.reg_write("if", 1)
                    vm.reg_write("ecx", 5)
                    assert _run(vm, bytes.fromhex(prefix + code))[0] == winemu.EXIT_PRIVILEGED, (is_64bit, code)
                    assert vm.pc == CODE
                    assert vm.reg_read("ecx") == 5
                    assert vm.reg_read("if") == 1

    def test_cpuid_and_privileged(self):
        vm = _vm()
        assert _run(vm, bytes.fromhex("31c0 0fa2"))[1] == winemu.FAULT_SYSCALL
        assert struct.pack("<III", vm.reg_read("ebx"), vm.reg_read("edx"), vm.reg_read("ecx")) == b"GenuineIntel"
        assert _run(vm, bytes.fromhex("f4"))[0] == winemu.EXIT_PRIVILEGED


class TestUntouchedPages(unittest.TestCase):
    def test_protect_and_query(self):
        # memory that was allocated but never touched answers like any other, on both engines
        answers = []
        for engine in ("unicorn", "rust"):
            with mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": engine}):
                emu = emulator(b"\xc3")
            buf = emu.alloc(0x1000)
            addr = API_HANDLERS["VirtualAlloc"].func(emu, [0, 0x3000, 0x3000, 0x40])
            assert addr and emu.is_mapped(addr + 0x1000)
            query = API_HANDLERS["VirtualQuery"].func
            assert query(emu, [addr + 0x1000, buf, 28]) == 28
            before = struct.unpack("<7I", emu.read(buf, 28))[5]
            # PAGE_READONLY, with a place for the old protection
            assert API_HANDLERS["VirtualProtect"].func(emu, [addr + 0x1000, 0x1000, 2, buf + 0x100]) == 1
            old = struct.unpack("<I", emu.read(buf + 0x100, 4))[0]
            assert query(emu, [addr + 0x1000, buf, 28]) == 28
            after = struct.unpack("<7I", emu.read(buf, 28))[5]
            answers.append((before, old, after, emu.perms(addr + 0x1000), emu.perms(addr)))
        assert answers[0] == answers[1] == (0x40, 0x40, 2, 1, 7), answers


@mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": "rust"})
class TestIcicleExceptions(test_emulation.TestExceptions):
    """
    The exception tests of the Unicorn engine, on Icicle.
    """

    def test_engine(self):
        assert isinstance(emulator(b"\xc3"), IcicleWindowsEmulator)

    def test_cli_and_port_io_raise(self):
        # nop; cli / in al, dx / out dx, al: STATUS_PRIVILEGED_INSTRUCTION at the instruction
        for opcode in (0xFA, 0xFB, 0xEC, 0xEE):
            emu = emulator(bytes((0x90, opcode, 0xC3)))
            emu.start()
            stop = emu.run(max_blocks=1000)
            assert stop.reason is StopReason.ERROR
            assert stop.detail == f"unhandled exception 0xc0000096 at {IMAGE_BASE + CODE_RVA + 1:#x}", stop

    def test_tracing_zeroed_data_is_cheap(self):
        # pointers into zeroed memory are tried as import wrappers by the thousand: none may leave thousands of
        # translated instructions behind
        emu = emulator(b"\xc3")
        emu.start()
        region = emu.alloc(0x100000)
        emu.write(region + 0x8000, b"\x90\x90\x40")
        before = len(emu.vm.lifted_instructions())
        for offset in (*range(0x1000, 0x41000, 0x1000), 0x8000):
            assert emu.trace_to_api(region + offset) is None
        assert len(emu.vm.lifted_instructions()) - before < 200

    def test_returns(self):
        emu = emulator(b"\xb8\x07\x00\x00\x00\xc3")
        emu.start()
        assert emu.run(max_blocks=1000).reason is StopReason.RETURNED
        assert emu.reg("eax") == 7
        assert emu.read(IMAGE_BASE + CODE_RVA, 1) == b"\xb8"


@mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": "rust"})
class TestIcicleApiHandlers(test_emulation.TestApiHandlers):
    """
    The API handler tests, on Icicle.
    """


@mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": "rust"})
class TestIcicleThreads(test_emulation.TestThreads):
    """
    The scheduler tests, on Icicle.
    """


@mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": "rust"})
class TestIcicleComObjects(test_emulation.TestComObjects):
    """
    The COM object tests, on Icicle.
    """


@mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": "rust"})
class TestIcicleWindowMessages(test_emulation.TestWindowMessages):
    """
    The window message tests, on Icicle.
    """


@mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": "rust"})
class TestIcicleBrokenImages(test_emulation.TestBrokenImages):
    """
    The broken image tests, on Icicle.
    """


@mock.patch.dict(os.environ, {"ANGR_UNPACKER_ENGINE": "rust"})
class TestIcicleTimers(test_emulation.TestTimers):
    """
    The timer tests on Icicle.
    """


if __name__ == "__main__":
    unittest.main()

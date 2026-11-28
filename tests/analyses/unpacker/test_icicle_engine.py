#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import struct
import unittest
from unittest import mock

from angr.analyses.unpacker.emulation import StopReason
from angr.analyses.unpacker.emulation.apis import API_HANDLERS
from angr.analyses.unpacker.emulation.icicle_environment import PROCESSORS_DIR, IcicleWindowsEmulator
from angr.rustylib import winemu
from angr.rustylib.winemu import WinVm

from . import test_emulation
from .samples import IMAGE_BASE, needs_sleigh_fixes
from .test_emulation import CODE_RVA, emulator

CODE = 0x400000


def _vm(is_64bit: bool = False) -> WinVm:
    vm = WinVm(is_64bit, PROCESSORS_DIR)
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
        # We call a nop sled, and then stosd and push write over the nop sled. Each instruction must take effect
        # exactly once.
        vm = _vm()
        vm.mem_write(CODE + 0x100, b"\x90" * 16 + b"\xc3")
        code = bytes.fromhex("e8fb000000 bf00014000 b844332211 ab bc10014000 6888776655")
        assert _run(vm, code) == (winemu.EXIT_EXCEPTION, winemu.FAULT_SYSCALL, 3)
        assert vm.mem_read(CODE + 0x100, 16) == bytes.fromhex("44332211") + b"\x90" * 8 + bytes.fromhex("88776655")
        assert vm.reg_read("edi") == CODE + 0x104
        assert vm.reg_read("esp") == CODE + 0x10C
        assert vm.smc_count == 1

    def test_redundant_rex_prefix(self):
        # es: rex.w rex.w mov [rax], rdx
        # The CPU ignores the first REX prefix, but SLEIGH rejects the first REX prefix.
        vm = _vm(True)
        vm.reg_write("rax", 0x500100)
        vm.reg_write("rdx", 0x1122334455667788)
        assert _run(vm, bytes.fromhex("26 48 48 89 10"))[1] == winemu.FAULT_SYSCALL
        assert vm.mem_read(0x500100, 8) == struct.pack("<Q", 0x1122334455667788)
        assert vm.fixups == 1

    @needs_sleigh_fixes
    def test_flags(self):
        vm = _vm()
        # mov eax, 0x80000001; shr eax, 1; pushfd
        # The imm8 form of shr must set OF to the old sign, and pushfd must keep bit 1 set.
        _run(vm, bytes.fromhex("b801000080 c1e801 9c"))
        flags = struct.unpack("<I", vm.mem_read(vm.reg_read("esp"), 4))[0]
        assert flags & 0x803 == 0x803
        # mov al, 0x0f; add al, 1; pushfd. The add must set the auxiliary carry.
        _run(vm, bytes.fromhex("b00f 0401 9c"))
        assert struct.unpack("<I", vm.mem_read(vm.reg_read("esp"), 4))[0] & 0x10

    @needs_sleigh_fixes
    def test_x64_zero_extension_and_shift_flags(self):
        vm = _vm(True)
        vm.mem_write(0x500100, struct.pack("<I", 0x11223344))
        vm.reg_write("rax", 0x500100)
        vm.reg_write("r10", 0xF6620AA00)
        # `xchg [rax], r10d` must clear the upper half of r10.
        _run(vm, bytes.fromhex("448710"))
        assert vm.reg_read("r10") == 0x11223344
        # `shr di, cl` with cl = 0 must keep AF.
        vm.reg_write("rcx", 0)
        vm.reg_write("eflags", 0x12)
        _run(vm, bytes.fromhex("66d3ef 9c"))
        assert struct.unpack("<Q", vm.mem_read(vm.reg_read("rsp"), 8))[0] & 0x10

    def test_precise_faults(self):
        # A fault must leave the registers as they were before the instruction.
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
        # idiv ecx. The quotient 2**31 does not fit, so the CPU raises a divide error before any register changes.
        assert _run(vm, bytes.fromhex("f7f9"))[:2] == (winemu.EXIT_EXCEPTION, winemu.FAULT_DIVIDE)
        assert vm.pc == CODE
        assert vm.reg_read("eax") == 0x80000000

    @needs_sleigh_fixes
    def test_16bit_addressing(self):
        # An operand with the 0x67 prefix uses a 16-bit offset, which is relative to the FS base in this test.
        # The stack still uses the 32-bit esp.
        vm = _vm()
        vm.reg_write("fs_base", 0x500000)
        vm.mem_write(0x500030, struct.pack("<I", 0x11223344))
        # mov ebx, fs:[0x30]; push dword fs:[0x30]; pop dword fs:[0x40]
        _run(vm, bytes.fromhex("64678b1e3000 6764ff363000 64678f064000"))
        assert vm.reg_read("ebx") == 0x11223344
        assert vm.reg_read("esp") == 0x500F00
        assert vm.mem_read(0x500040, 4) == struct.pack("<I", 0x11223344)

    @needs_sleigh_fixes
    def test_descriptor_instructions(self):
        vm = _vm()
        # We run lsl and lar on the user data selector, and then lsl on the null selector, which must keep the
        # destination.
        vm.reg_write("edi", 0x23)
        _run(vm, bytes.fromhex("0f03df 0f02c7"))
        assert (vm.reg_read("ebx"), vm.reg_read("eax"), vm.reg_read("ZF")) == (0xFFFFFFFF, 0x00CFF300, 1)
        vm.reg_write("edi", 0)
        _run(vm, bytes.fromhex("0f03df"))
        assert (vm.reg_read("ebx"), vm.reg_read("ZF")) == (0xFFFFFFFF, 0)
        # verr and verw must report that a code segment is readable and not writable.
        for code, selector, zf in (("0f00e7", 0x1B, 1), ("0f00ef", 0x1B, 0), ("0f00ef", 0x3B, 1), ("0f00e7", 0x8, 0)):
            vm.reg_write("edi", selector)
            _run(vm, bytes.fromhex(code))
            assert vm.reg_read("ZF") == zf, (code, selector)
        # xgetbv must report that the x87 state and the SSE state are enabled.
        vm.reg_write("ecx", 0)
        _run(vm, bytes.fromhex("0f01d0"))
        assert (vm.reg_read("eax"), vm.reg_read("edx")) == (3, 0)

    def test_user_ops_and_wide_registers(self):
        vm = _vm()
        handled = dict(vm.user_ops())
        assert handled["segment"] == "helper" and handled["cpuid"] == "lifter"
        # The VM raises "unimplemented", which is 0x100a, when the program runs a user op that has no implementation.
        assert handled["xsavec"] == ""
        value = bytes(range(16))
        vm.reg_write_bytes("xmm3", value)
        # movdqa xmm1, xmm3
        _run(vm, bytes.fromhex("660f6fcb"))
        assert vm.reg_read_bytes("xmm1") == value

    def test_privileged_and_absent_instructions(self):
        # wrmsr, invlpg [eax] and mwait are privileged.
        # vmcall, vmxon [eax], vmmcall, xbegin and xtest are undefined opcodes.
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
        # xacquire lock inc dword [eax]. An HLE prefix is only a hint, so the instruction must run.
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
            # We move the emulated clock forward by 250 ms, as a Sleep does, and run rdtscp.
            vm.clock = 1250
            _run(vm, bytes.fromhex("0f01f9"))
            third = vm.reg_read("edx") << 32 | vm.reg_read("eax")
            runs.append((first, second, third))
        # Every run must read the same values. Two adjacent reads are a few cycles apart, and the reads around the
        # sleep are 250 ms apart at 3.6 GHz.
        assert runs[0] == runs[1]
        first, second, third = runs[0]
        assert first // 3_600_000 == 1000 and 0 < second - first < 100
        assert 0 <= third - second - 250 * 3_600_000 < 100
        assert vm.reg_read("ecx") == 0

    @needs_sleigh_fixes
    def test_user_mode_interrupt_flag(self):
        # push 0; popfd; pushfd; pop eax. IF must stay set, as in any user-mode thread.
        vm = _vm()
        vm.reg_write("if", 1)
        assert _run(vm, bytes.fromhex("6a00 9d 9c 58"))[1] == winemu.FAULT_SYSCALL
        assert vm.reg_read("eax") == 0x202

    @needs_sleigh_fixes
    def test_io_privileged_instructions(self):
        # cli, sti, in, out and the string forms of in and out need I/O privilege. Each instruction must fault and
        # change nothing.
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
        # Memory that the program allocated but never touched must answer like any other memory on both engines.
        answers = []
        for engine in ("unicorn", "icicle"):
            with mock.patch.object(test_emulation, "ENGINE", engine):
                emu = emulator()
            buf = emu.alloc(0x1000)
            addr = API_HANDLERS["VirtualAlloc"].func(emu, [0, 0x3000, 0x3000, 0x40])
            assert addr and emu.is_mapped(addr + 0x1000)
            query = API_HANDLERS["VirtualQuery"].func
            assert query(emu, [addr + 0x1000, buf, 28]) == 28
            before = struct.unpack("<7I", emu.read(buf, 28))[5]
            # We set PAGE_READONLY and pass a buffer for the old protection.
            assert API_HANDLERS["VirtualProtect"].func(emu, [addr + 0x1000, 0x1000, 2, buf + 0x100]) == 1
            old = struct.unpack("<I", emu.read(buf + 0x100, 4))[0]
            assert query(emu, [addr + 0x1000, buf, 28]) == 28
            after = struct.unpack("<7I", emu.read(buf, 28))[5]
            answers.append((before, old, after, emu.perms(addr + 0x1000), emu.perms(addr)))
        assert answers[0] == answers[1] == (0x40, 0x40, 2, 1, 7), answers


@mock.patch.object(test_emulation, "ENGINE", "icicle")
class TestIcicleExceptions(test_emulation.TestExceptions):
    """
    These tests run the exception tests on Icicle.
    """

    def test_engine(self):
        assert isinstance(emulator(), IcicleWindowsEmulator)

    @needs_sleigh_fixes
    def test_cli_and_port_io_raise(self):
        # Each sample runs a nop and then cli, sti, `in al, dx` or `out dx, al`, which must raise
        # STATUS_PRIVILEGED_INSTRUCTION at the address of the instruction.
        for name in ("cli.exe", "sti.exe", "in.exe", "out.exe"):
            emu = emulator(name)
            emu.start()
            stop = emu.run(max_blocks=1000)
            assert stop.reason is StopReason.ERROR
            assert stop.detail == f"unhandled exception 0xc0000096 at {IMAGE_BASE + CODE_RVA + 1:#x}", stop

    def test_tracing_zeroed_data_is_cheap(self):
        # The unpacker traces thousands of pointers into zeroed memory as import wrappers. A trace must not leave
        # many translated instructions behind.
        emu = emulator()
        emu.start()
        region = emu.alloc(0x100000)
        emu.write(region + 0x8000, b"\x90\x90\x40")
        before = len(emu.vm.lifted_instructions())
        for offset in (*range(0x1000, 0x41000, 0x1000), 0x8000):
            assert emu.trace_to_api(region + offset) is None
        assert len(emu.vm.lifted_instructions()) - before < 200

    def test_returns(self):
        # mov eax, 7; ret
        emu = emulator("mov_eax_7.exe")
        emu.start()
        assert emu.run(max_blocks=1000).reason is StopReason.RETURNED
        assert emu.reg("eax") == 7
        assert emu.read(IMAGE_BASE + CODE_RVA, 1) == b"\xb8"


@mock.patch.object(test_emulation, "ENGINE", "icicle")
class TestIcicleApiHandlers(test_emulation.TestApiHandlers):
    """
    These tests run the API handler tests on Icicle.
    """


@mock.patch.object(test_emulation, "ENGINE", "icicle")
class TestIcicleThreads(test_emulation.TestThreads):
    """
    These tests run the scheduler tests on Icicle.
    """


@mock.patch.object(test_emulation, "ENGINE", "icicle")
class TestIcicleComObjects(test_emulation.TestComObjects):
    """
    These tests run the COM object tests on Icicle.
    """


@mock.patch.object(test_emulation, "ENGINE", "icicle")
class TestIcicleWindowMessages(test_emulation.TestWindowMessages):
    """
    These tests run the window message tests on Icicle.
    """


@mock.patch.object(test_emulation, "ENGINE", "icicle")
class TestIcicleBrokenImages(test_emulation.TestBrokenImages):
    """
    These tests run the broken image tests on Icicle.
    """


@mock.patch.object(test_emulation, "ENGINE", "icicle")
class TestIcicleTimers(test_emulation.TestTimers):
    """
    These tests run the timer tests on Icicle.
    """


if __name__ == "__main__":
    unittest.main()

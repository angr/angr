#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import struct
import unittest

import angr
from angr.analyses.cfg.go_prologue import find_go_stack_check_preambles, go_preamble_supported
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

BASE = 0x400000


def _w(word: int) -> bytes:
    return struct.pack("<I", word)


# The preamble encodings the Go compiler emits, one lambda per encoding, parameterized by the byte
# distance from the end of the preamble to the stack-growth trampoline. Taken from `go tool objdump`
# output of the fixture binaries listed in GO_FIXTURES.

AMD64_BODY = b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3"  # push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
AMD64_PREAMBLES = [
    # cmp rsp, [r14 + 0x10]; jbe
    lambda d: bytes.fromhex("493b6610") + b"\x76" + bytes([d]),
    lambda d: bytes.fromhex("493b6610") + b"\x0f\x86" + struct.pack("<i", d),
    # the same check against g.stackguard1
    lambda d: bytes.fromhex("493b6618") + b"\x76" + bytes([d]),
    # lea r12, [rsp + disp]; cmp r12, [r14 + 0x10]; jbe
    lambda d: bytes.fromhex("4c8d6424f8") + bytes.fromhex("4d3b6610") + b"\x76" + bytes([d]),
    lambda d: bytes.fromhex("4c8d6424f8") + bytes.fromhex("4d3b6610") + b"\x0f\x86" + struct.pack("<i", d),
    lambda d: bytes.fromhex("4c8da42400ffffff") + bytes.fromhex("4d3b6610") + b"\x76" + bytes([d]),
    lambda d: bytes.fromhex("4c8da42400ffffff") + bytes.fromhex("4d3b6618") + b"\x0f\x86" + struct.pack("<i", d),
    # mov r12, rsp; sub r12, imm32; jb; cmp r12, [r14 + 0x10]; jbe
    lambda d: (
        bytes.fromhex("4989e44981ec880f0000")
        + b"\x0f\x82"
        + struct.pack("<i", d + 6)
        + bytes.fromhex("4d3b6610")
        + b"\x76"
        + bytes([d])
    ),
    # windows only: reload g through runtime.tls_g first
    lambda d: bytes.fromhex("4c8b3500000000654d8b364d8b36") + bytes.fromhex("493b6610") + b"\x76" + bytes([d]),
]

X86_BODY = b"\x83\xec\x0c\x31\xc0\x83\xc4\x0c\xc3"  # sub esp, 0xc; xor eax, eax; add esp, 0xc; ret
X86_WIN_G = bytes.fromhex("8b0d00000000648b098b09")  # mov ecx, [tls_g]; mov ecx, fs:[ecx]; mov ecx, [ecx]
X86_WIN_OLD_G = bytes.fromhex("648b0d140000008b8900000000")  # mov ecx, fs:[0x14]; mov ecx, [ecx]
X86_LINUX_G = bytes.fromhex("658b0d000000008b89fcffffff")  # mov ecx, gs:[0]; mov ecx, [ecx - 4]


def _x86_preambles(g: bytes):
    return [
        # cmp esp, [ecx + 8]; jbe
        lambda d: g + bytes.fromhex("3b6108") + b"\x76" + bytes([d]),
        lambda d: g + bytes.fromhex("3b6108") + b"\x0f\x86" + struct.pack("<i", d),
        # the same check against g.stackguard1
        lambda d: g + bytes.fromhex("3b610c") + b"\x76" + bytes([d]),
        # lea eax, [esp + disp]; cmp eax, [ecx + 8]; jbe
        lambda d: g + bytes.fromhex("8d4424fc") + bytes.fromhex("3b4108") + b"\x0f\x86" + struct.pack("<i", d),
        lambda d: g + bytes.fromhex("8d8424c0fcffff") + bytes.fromhex("3b410c") + b"\x76" + bytes([d]),
        # mov eax, esp; sub eax, imm32; jb; cmp eax, [ecx + 8]; jbe
        lambda d: (
            g
            + bytes.fromhex("89e02d801f0000")
            + b"\x72"
            + bytes([d + 5])
            + bytes.fromhex("3b4108")
            + b"\x76"
            + bytes([d])
        ),
    ]


X86_PREAMBLES = _x86_preambles(X86_WIN_G) + _x86_preambles(X86_WIN_OLD_G) + _x86_preambles(X86_LINUX_G)

ARM_BODY = _w(0xE52DE004) + _w(0xE3A00000) + _w(0xE49DF004)  # push {lr}; mov r0, #0; pop {pc}


def _arm_bls(d: int) -> bytes:
    # arm branches are pc-relative in words, with the two-instruction pipeline offset
    return _w(0x9A000000 | (((d - 4) // 4) & 0xFFFFFF))


ARM_PREAMBLES = [
    # ldr r1, [r10, #8]; cmp sp, r1; bls
    lambda d: _w(0xE59A1008) + _w(0xE15D0001) + _arm_bls(d),
    # the same check against g.stackguard1
    lambda d: _w(0xE59A100C) + _w(0xE15D0001) + _arm_bls(d),
    # + sub r2, sp, #imm
    lambda d: _w(0xE59A1008) + _w(0xE24D2014) + _w(0xE1520001) + _arm_bls(d),
    # + movw r11, #imm16; subs r2, sp, r11
    lambda d: _w(0xE59A1008) + _w(0xE301BF94) + _w(0xE05D200B) + _w(0x21520001) + _arm_bls(d),
    # + ldr r11, [pc, #imm]; add r2, sp, r11
    lambda d: _w(0xE59A1008) + _w(0xE59FB4A8) + _w(0xE08D200B) + _w(0xE1520001) + _arm_bls(d),
    # + ldr r11, [pc, #imm]; subs r2, sp, r11
    lambda d: _w(0xE59A1008) + _w(0xE59FB098) + _w(0xE05D200B) + _w(0x21520001) + _arm_bls(d),
]

AARCH64_BODY = _w(0xD2800000) + _w(0xD65F03C0)  # movz x0, #0; ret


def _a64_bls(d: int) -> bytes:
    return _w(0x54000009 | ((((d + 4) // 4) & 0x7FFFF) << 5))


def _a64_bcc(d: int) -> bytes:
    # the overflow check always sits 12 bytes ahead of the end of the preamble
    return _w(0x54000003 | ((((d + 12) // 4) & 0x7FFFF) << 5))


AARCH64_PREAMBLES = [
    # ldr x16, [x28, #0x10]; cmp sp, x16; b.ls
    lambda d: _w(0xF9400B90) + _w(0xEB3063FF) + _a64_bls(d),
    # the same check against g.stackguard1
    lambda d: _w(0xF9400F90) + _w(0xEB3063FF) + _a64_bls(d),
    # go1.18: mov x17, sp; cmp x17, x16
    lambda d: _w(0xF9400B90) + _w(0x910003F1) + _w(0xEB10023F) + _a64_bls(d),
    # + sub x17, sp, #imm12
    lambda d: _w(0xF9400B90) + _w(0xD10103F1) + _w(0xEB10023F) + _a64_bls(d),
    # + subs x17, sp, #imm12; b.cc
    lambda d: _w(0xF9400B90) + _w(0xF13E43F1) + _a64_bcc(d) + _w(0xEB10023F) + _a64_bls(d),
    # + movz x27, #imm16; subs x17, sp, x27; b.cc
    lambda d: _w(0xF9400B90) + _w(0xD283F61B) + _w(0xEB3B63F1) + _a64_bcc(d) + _w(0xEB10023F) + _a64_bls(d),
    # + movz/movk x27; subs x17, sp, x27; b.cc
    lambda d: (
        _w(0xF9400B90) + _w(0xD29FF21B) + _w(0xF2A0003B) + _w(0xEB3B63F1) + _a64_bcc(d) + _w(0xEB10023F) + _a64_bls(d)
    ),
    # go1.17 emitted the same shapes over the x1/x2 scratch pair
    lambda d: _w(0xF9400B81) + _w(0x910003E2) + _w(0xEB01005F) + _a64_bls(d),
    lambda d: _w(0xF9400B81) + _w(0xD100C3E2) + _w(0xEB01005F) + _a64_bls(d),
    lambda d: _w(0xF9400B81) + _w(0xD283F61B) + _w(0xEB3B63E2) + _a64_bcc(d) + _w(0xEB01005F) + _a64_bls(d),
]


def _tail_jump(arch: str, delta: int) -> bytes:
    """A jump back `delta` bytes, standing in for the morestack trampoline's tail jump."""
    if arch in ("AMD64", "X86"):
        return b"\xeb" + struct.pack("<b", delta - 2)
    if arch == "AARCH64":
        return _w(0x14000000 | ((delta // 4) & 0x3FFFFFF))
    return _w(0xEA000000 | (((delta - 8) // 4) & 0xFFFFFF))


ARCHES = {
    # arch name -> (preamble builders, function body, entry stub, alignment)
    "AMD64": (AMD64_PREAMBLES, AMD64_BODY, b"\x31\xc0\xc3", 16),
    "X86": (X86_PREAMBLES, X86_BODY, b"\x31\xc0\xc3", 16),
    "ARMEL": (ARM_PREAMBLES, ARM_BODY, _w(0xE12FFF1E), 16),
    "AARCH64": (AARCH64_PREAMBLES, AARCH64_BODY, _w(0xD65F03C0), 16),
}


def _go_blob(arch: str) -> tuple[bytes, list[int], list[int]]:
    """
    Build a blob holding one Go-style function per preamble encoding. Returns the blob, the function
    entries, and the length of the preamble within each function.
    """

    preambles, body, stub, align = ARCHES[arch]
    blob = bytearray(stub)
    entries, deltas = [], []
    for make_preamble in preambles:
        blob += b"\x00" * (-len(blob) % align)
        entry = len(blob)
        preamble = make_preamble(len(body))
        entries.append(BASE + entry)
        deltas.append(len(preamble))
        blob += preamble + body
        # the morestack trampoline the stack check branches to
        blob += _tail_jump(arch, entry - len(blob))
    return bytes(blob), entries, deltas


class TestGoPreambleEncodings(unittest.TestCase):
    def _check(self, arch):
        blob, entries, deltas = _go_blob(arch)
        found = {start: end for start, end, _ in find_go_stack_check_preambles(blob, arch, BASE)}
        assert sorted(found) == [e - BASE for e in entries]
        assert [found[e - BASE] - (e - BASE) for e in entries] == deltas
        return deltas

    def test_amd64(self):
        assert self._check("AMD64") == [6, 10, 6, 11, 15, 14, 18, 22, 20]

    def test_x86(self):
        assert self._check("X86") == [
            16, 20, 16, 24, 23, 25,
            18, 22, 18, 26, 25, 27,
            18, 22, 18, 26, 25, 27,
        ]  # fmt: skip

    def test_armel(self):
        assert self._check("ARMEL") == [12, 12, 16, 20, 20, 20]

    def test_aarch64(self):
        assert self._check("AARCH64") == [12, 12, 16, 16, 20, 24, 28, 16, 16, 24]

    def test_backward_branch_is_rejected(self):
        # a stack-growth branch always goes forward, to a trampoline appended after the body
        assert not list(find_go_stack_check_preambles(bytes.fromhex("493b661076fe") + AMD64_BODY, "AMD64", BASE))
        assert not list(find_go_stack_check_preambles(X86_WIN_G + bytes.fromhex("3b610876fe"), "X86", BASE))
        assert not list(find_go_stack_check_preambles(_w(0xE59A1008) + _w(0xE15D0001) + _w(0x9AFFFFFE), "ARMEL", BASE))
        assert not list(
            find_go_stack_check_preambles(_w(0xF9400B90) + _w(0xEB3063FF) + _w(0x54FFFFE9), "AARCH64", BASE)
        )

    def test_matches_must_be_instruction_aligned(self):
        for arch in ("ARMEL", "AARCH64"):
            blob, _entries, _deltas = _go_blob(arch)
            # the same bytes at an address that is not a multiple of 4 cannot be an instruction
            assert not list(find_go_stack_check_preambles(blob, arch, BASE + 2))
            # an unaligned occurrence must not swallow the aligned one that follows it
            padded = b"\x00" * 2 + blob[:8] + blob
            aligned = [s for s, _, _ in find_go_stack_check_preambles(blob, arch, BASE)]
            assert aligned
            assert [s - 10 for s, _, _ in find_go_stack_check_preambles(padded, arch, BASE + 2)] == aligned

    def test_patterns_are_arch_gated(self):
        for arch in ARCHES:
            blob, _entries, _deltas = _go_blob(arch)
            for other in ARCHES:
                if other != arch:
                    assert not list(find_go_stack_check_preambles(blob, other, BASE))
            # an architecture with no pattern table of its own never matches
            assert not go_preamble_supported("MIPS32")
            assert not list(find_go_stack_check_preambles(blob, "MIPS32", BASE))

    def _check_prologue_scan(self, arch):
        blob, entries, deltas = _go_blob(arch)
        proj = angr.load_shellcode(blob, arch, load_address=BASE)
        # prologue scanning is the only source of function starts here
        cfg = proj.analyses.CFGFast(
            symbols=False, function_prologues=True, force_smart_scan=False, force_complete_scan=False
        )
        funcs = set(cfg.kb.functions)
        assert funcs.issuperset(entries)
        # the conventional prologue the preamble covers must not be reported as a function start
        assert not funcs.intersection(e + d for e, d in zip(entries, deltas))

    def test_prologue_scan_reports_go_function_entry_amd64(self):
        self._check_prologue_scan("AMD64")

    def test_prologue_scan_reports_go_function_entry_x86(self):
        self._check_prologue_scan("X86")

    def test_prologue_scan_reports_go_function_entry_armel(self):
        self._check_prologue_scan("ARMEL")

    def test_prologue_scan_reports_go_function_entry_aarch64(self):
        self._check_prologue_scan("AARCH64")


# Fixtures built from tests_src/language_detector/langdetect_go.go by build_go_cross.sh. The Go
# releases span the preamble forms the compiler has emitted: go1.17 (x1/x2 on arm64, fs:[0x14] on
# windows/386), go1.18 (x16/x17 compared through x17), go1.20 (compares sp directly), go1.22
# (runtime.tls_g on windows/386) and the current toolchain.
GO_VERSIONS = ("go1.17.13", "go1.18.10", "go1.20.14", "go1.22.5", "go1.27.1")
GO_CURRENT = "go1.27.1"
GO_TARGETS = {
    # target -> (path template taking the Go version suffix, archinfo name)
    "linux_386": ("i386/langdetect_go{}", "X86"),
    "windows_386": ("i386/windows/langdetect_go{}.exe", "X86"),
    "linux_arm": ("armel/langdetect_go{}", "ARMEL"),
    "linux_arm64": ("aarch64/langdetect_go{}", "AARCH64"),
    "windows_arm64": ("aarch64/windows/langdetect_go{}.exe", "AARCH64"),
}
# amd64 is built by build.sh and build_go_cross.sh with one toolchain each
AMD64_FIXTURES = {
    ("linux_amd64", "go1.22.5"): ("x86_64/langdetect_go", "AMD64"),
    ("windows_amd64", GO_CURRENT): ("x86_64/windows/langdetect_go.exe", "AMD64"),
}

GO_FIXTURES = {
    (target, version): (template.format("" if version == GO_CURRENT else f"_{version}"), arch)
    for target, (template, arch) in GO_TARGETS.items()
    for version in GO_VERSIONS
} | AMD64_FIXTURES

# every fixture has at least this many preambles; the counts run about 5% higher
FIXTURE_MINIMA = {
    ("linux_386", "go1.17.13"): 1080,
    ("linux_386", "go1.18.10"): 1100,
    ("linux_386", "go1.20.14"): 1180,
    ("linux_386", "go1.22.5"): 1250,
    ("linux_386", "go1.27.1"): 1440,
    ("windows_386", "go1.17.13"): 1110,
    ("windows_386", "go1.18.10"): 1130,
    ("windows_386", "go1.20.14"): 1190,
    ("windows_386", "go1.22.5"): 1290,
    ("windows_386", "go1.27.1"): 1560,
    ("linux_arm", "go1.17.13"): 1050,
    ("linux_arm", "go1.18.10"): 1060,
    ("linux_arm", "go1.20.14"): 1130,
    ("linux_arm", "go1.22.5"): 1170,
    ("linux_arm", "go1.27.1"): 1360,
    ("linux_arm64", "go1.17.13"): 990,
    ("linux_arm64", "go1.18.10"): 1020,
    ("linux_arm64", "go1.20.14"): 1070,
    ("linux_arm64", "go1.22.5"): 1130,
    ("linux_arm64", "go1.27.1"): 1310,
    ("windows_arm64", "go1.17.13"): 1010,
    ("windows_arm64", "go1.18.10"): 1040,
    ("windows_arm64", "go1.20.14"): 1070,
    ("windows_arm64", "go1.22.5"): 1150,
    ("windows_arm64", "go1.27.1"): 1360,
    ("linux_amd64", "go1.22.5"): 1080,
    ("windows_amd64", "go1.27.1"): 1330,
}

# cle does not read the Go symbol table out of a PE, so entries are pinned instead. Addresses of
# main.main, main.fibonacci, runtime.main and one more runtime function, from `go tool objdump`.
PE_KNOWN_ENTRIES = {
    ("windows_386", "go1.17.13"): [0x488100, 0x4880A0, 0x433640, 0x406480],
    ("windows_386", "go1.18.10"): [0x489630, 0x4895D0, 0x434530, 0x43C860],
    ("windows_386", "go1.20.14"): [0x48E560, 0x48E500, 0x4360C0, 0x43E9E0],
    ("windows_386", "go1.22.5"): [0x48A6E0, 0x48A680, 0x437AE0, 0x4411F0],
    ("windows_386", "go1.27.1"): [0x4AA560, 0x4AA500, 0x44DF60, 0x456FE0],
    ("windows_arm64", "go1.17.13"): [0x100096A50, 0x1000969C0, 0x100036430, 0x100007170],
    ("windows_arm64", "go1.18.10"): [0x10008EEA0, 0x10008EE20, 0x1000341C0, 0x10003CF90],
    ("windows_arm64", "go1.20.14"): [0x10008D240, 0x10008D1C0, 0x100033970, 0x10003C540],
    ("windows_arm64", "go1.22.5"): [0x10008CCC0, 0x10008CC40, 0x1000364B0, 0x100040FD0],
    ("windows_arm64", "go1.27.1"): [0x14009FDC0, 0x14009FD50, 0x140044280, 0x14004D9E0],
    ("windows_amd64", "go1.27.1"): [0x1400A7360, 0x1400A73C0, 0x140047E20, 0x14009D140],
}

# one scoped CFG per target, plus the oldest arm64 codegen: (region, minimum preambles in it)
SCOPED_CFG_REGIONS = {
    ("linux_amd64", "go1.22.5"): ((0x45D100, 0x45E100), 25),
    ("linux_386", GO_CURRENT): ((0x80C3B70, 0x80C4B70), 31),
    ("linux_arm", GO_CURRENT): ((0x9416C, 0x9516C), 28),
    ("linux_arm64", GO_CURRENT): ((0x7E590, 0x7F590), 31),
    ("linux_arm64", "go1.17.13"): ((0x70DE0, 0x71DE0), 24),
    ("windows_amd64", GO_CURRENT): ((0x140071F20, 0x140072F20), 31),
    ("windows_386", GO_CURRENT): ((0x47C640, 0x47D640), 50),
    ("windows_arm64", GO_CURRENT): ((0x14006D120, 0x14006E120), 30),
}

NON_GO_BINARIES = {
    "AMD64": ["x86_64/fauxware", "x86_64/true", "x86_64/libc.so.6"],
    "X86": ["i386/fauxware", "i386/nl", "i386/simple_windows.exe", "i386/libc.so.6"],
    "ARMEL": ["armel/fauxware", "armel/sha224sum", "armel/libc.so.6"],
    "AARCH64": ["aarch64/test_arrays", "aarch64/libc.so.6"],
}


def _preambles(proj, lo=None, hi=None) -> dict[int, int]:
    """Detected preamble start -> end, as mapped addresses."""

    obj = proj.loader.main_object
    out = {}
    for rva, backer in obj.memory.backers():
        base = obj.mapped_base + rva
        for start, end, _target in find_go_stack_check_preambles(bytes(backer), proj.arch.name, base):
            if lo is None or lo <= base + start < hi:
                out[base + start] = base + end
    return out


def _fixture_tests(cls):
    """One test method per fixture, so a failure names the target and the Go version."""

    def bind(method, target, version):
        return lambda self: getattr(self, method)(target, version)

    for target, version in GO_FIXTURES:
        tag = f"{target}_{version.replace('.', '_')}"
        setattr(cls, f"test_preambles_land_on_real_entries_{tag}", bind("_check_fixture", target, version))
    for target, version in SCOPED_CFG_REGIONS:
        tag = f"{target}_{version.replace('.', '_')}"
        setattr(cls, f"test_scoped_cfg_recovers_go_entries_{tag}", bind("_check_scoped_cfg", target, version))
    return cls


@_fixture_tests
class TestGoPreambleOnRealBinaries(unittest.TestCase):
    def _project(self, target, version):
        path, arch = GO_FIXTURES[target, version]
        proj = angr.Project(os.path.join(test_location, path), auto_load_libs=False)
        assert proj.arch.name == arch
        return proj

    def _check_fixture(self, target, version):
        """Every preamble must sit on a real function entry, and nearly all entries must be found."""

        proj = self._project(target, version)
        starts = set(_preambles(proj))
        assert len(starts) >= FIXTURE_MINIMA[target, version]
        if target.startswith("windows_"):
            assert set(PE_KNOWN_ENTRIES[target, version]).issubset(starts)
        else:
            symbols = {s.rebased_addr for s in proj.loader.main_object.symbols if s.is_function}
            assert not starts - symbols

    def _check_scoped_cfg(self, target, version):
        (start, end), minimum = SCOPED_CFG_REGIONS[target, version]
        proj = self._project(target, version)
        preambles = _preambles(proj, start, end)
        assert len(preambles) >= minimum
        cfg = proj.analyses.CFGFast(
            regions=[(start, end)], symbols=False, force_smart_scan=False, force_complete_scan=False
        )
        funcs = set(cfg.kb.functions)
        assert set(preambles).issubset(funcs)
        # not a single function starts at the instruction the preamble ends on
        assert not funcs.intersection(preambles.values())

    def test_non_go_binaries_have_no_preambles(self):
        for arch, binaries in NON_GO_BINARIES.items():
            for binary in binaries:
                proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
                assert proj.arch.name == arch
                assert not _preambles(proj)


if __name__ == "__main__":
    unittest.main()

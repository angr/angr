#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import struct
import tempfile
import unittest

import angr

BASE = 0x140000000
TEXT, VMP, THEMIDA = 0x1000, 0x2000, 0x3000
API = 0x7FFF0000  # unmapped: an imported function

PUSH_ALL = bytes([0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x55]) + b"".join(bytes([0x41, 0x50 + i]) for i in range(8))
POP_ALL = b"".join(bytes([0x41, 0x5F - i]) for i in range(8)) + bytes([0x5D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58])


def rel32(src: int, size: int, dst: int) -> bytes:
    return struct.pack("<i", dst - (src + size))


def pe_header(sections) -> bytes:
    hdr = bytearray(0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x40)
    hdr[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x44, 0x8664, len(sections), 0, 0, 0, 0xF0, 0x22)
    opt = 0x58
    struct.pack_into("<HBB", hdr, opt, 0x20B, 14, 0)
    struct.pack_into("<I", hdr, opt + 16, TEXT)  # AddressOfEntryPoint
    struct.pack_into("<Q", hdr, opt + 24, BASE)
    struct.pack_into("<II", hdr, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", hdr, opt + 56, 0x4000, 0x400)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<I", hdr, opt + 108, 16)
    off = opt + 0xF0
    for name, rva, flags in sections:
        struct.pack_into("<8sIIII", hdr, off, name, 0x1000, rva, 0x1000, rva)
        struct.pack_into("<I", hdr, off + 36, flags)
        off += 40
    return bytes(hdr)


def build_image() -> bytes:
    img = bytearray(0x4000)
    img[:0x400] = pe_header(
        [(b".text", TEXT, 0x60000020), (b".vmp0", VMP, 0x60000020), (b".themida", THEMIDA, 0xE0000020)]
    )

    def put(rva, code):
        img[rva : rva + len(code)] = code

    # f: native prologue, then the virtualized region (VMProtect 3.x: jmp to "push <ref>; call <entry>")
    f, f_exit = TEXT, TEXT + 0x40
    put(f, b"\x48\x83\xec\x28" + b"\xe9" + rel32(BASE + f + 4, 5, BASE + VMP))
    put(f + 9, b"\xcc" * (f_exit - f - 9))
    put(f_exit, b"\x48\x83\xc4\x28\xc3")  # native continuation: add rsp, 0x28; ret
    # VMProtect entry stub and handler; it checks the pushed reference, saves everything, calls an API and exits
    put(VMP, b"\x68\x34\x12\x00\x00" + b"\xe8" + rel32(BASE + VMP + 5, 5, BASE + VMP + 0x100))
    h = VMP + 0x100
    code = b"\x9c\x50\x48\x8b\x44\x24\x18\x3d\x34\x12\x00\x00\x0f\x85" + rel32(BASE + h + 12, 6, BASE + VMP + 0x400)
    code += b"\x58" + PUSH_ALL + POP_ALL + b"\x9d\x48\x83\xc4\x10"  # pop rax; save; restore; popfq; add rsp, 16
    code += b"\x48\x8d\x05" + rel32(BASE + h + len(code), 7, BASE + VMP + 0x300)  # lea rax, [reentry]
    code += b"\x50\x48\xb8" + struct.pack("<Q", API) + b"\xff\xe0"  # push rax; mov rax, API; jmp rax
    put(h, code)
    # a re-entry stub placed in the space the virtualized body freed: only the VM reaches it
    put(f + 0x10, b"\x68\x34\x12\x00\x00\xe8" + rel32(BASE + f + 0x15, 5, BASE + h))
    put(VMP + 0x300, b"\xe9" + rel32(BASE + VMP + 0x300, 5, BASE + f_exit))  # re-entry, straight to the exit
    put(VMP + 0x400, b"\x0f\x0b")  # ud2: wrong reference
    # g: a normal function calling a helper in another section: not a VM entry
    g = TEXT + 0x100
    put(g, b"\x53\xe8" + rel32(BASE + g + 1, 5, BASE + VMP + 0x500) + b"\x5b\xc3")
    put(VMP + 0x500, b"\xb8\x02\x00\x00\x00\xc3")
    # VMProtect 3.6+ style: the push/call stub is built in place. It borrows rcx/rbx, restores them through
    # rbx-relative loads, leaves the reference on the stack and calls the entry.
    t = TEXT + 0x200
    stub = bytes.fromhex("51539c48c7c350000000488b4c1cc048c744241034120000488b5c1cb89d488d642408")
    put(t, b"\x48\x83\xec\x28" + stub + b"\xe8" + rel32(BASE + t + 4 + len(stub), 5, BASE + h))
    # k: Themida-style entry: jmp into the writable protector section, which starts with pushfq
    k = TEXT + 0x300
    put(k, b"\xe9" + rel32(BASE + k, 5, BASE + THEMIDA))
    put(THEMIDA, b"\x9c" + PUSH_ALL + b"\xeb\xfe")
    caller = TEXT + 0x380
    put(caller, b"\xe8" + rel32(BASE + caller, 5, BASE + k) + b"\xe8" + rel32(BASE + caller + 5, 5, BASE + t) + b"\xc3")
    return bytes(img)


class TestVMProtectedFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.path = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as fh:
            fh.write(build_image())

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.path)

    def _project(self):
        return angr.Project(
            self.path,
            main_opts={"backend": "blob", "arch": "AMD64", "base_addr": BASE, "entry_point": BASE + TEXT},
            auto_load_libs=False,
        )

    def test_entries(self):
        proj = self._project()
        a = proj.analyses.VMProtectedFunctions()
        by_stub = {f.stub_start - BASE: f for f in a.functions}
        assert sorted(by_stub) == [TEXT + 4, TEXT + 0x204, TEXT + 0x300], [hex(x) for x in by_stub]
        assert [s.name for s in a.protector_sections] == [".vmp0", ".themida"]
        assert a.unreachable_stubs == [BASE + TEXT + 0x10]

        f = by_stub[TEXT + 4]
        assert (f.protector, f.entry_kind, f.vm_entry) == ("vmprotect", "jmp", BASE + VMP)
        assert f.function_addr == BASE + TEXT and not f.whole_function
        kw = f.vmdeobfuscation_kwargs()
        assert kw["start_addr"] == BASE + TEXT and kw["deobfuscation_start_addr"] == BASE + VMP

        # the in-place stub starts after the native prologue, not at the call that ends it
        s = by_stub[TEXT + 0x204]
        assert (s.protector, s.entry_kind) == ("vmprotect", "call")
        assert s.entry_site == BASE + TEXT + 0x204 + 35

        t = by_stub[TEXT + 0x300]
        assert t.protector == "themida" and t.whole_function
        assert t.vmdeobfuscation_kwargs()["start_deobfuscation_immediately"]
        assert proj.kb.obfuscations.vm_protected_functions[t.stub_start] is t


if __name__ == "__main__":
    unittest.main()

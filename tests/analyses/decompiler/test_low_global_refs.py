#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import io
import unittest

import angr
from angr.calling_conventions import SimCCSystemVAMD64
from angr.sim_type import parse_signature


def _blob_project(code: bytes, base: int, extra: dict[int, bytes] | None = None) -> angr.Project:
    blob = bytearray(code.ljust(0x10400, b"\x00"))
    for off, data in (extra or {}).items():
        blob[off : off + len(data)] = data
    return angr.Project(
        io.BytesIO(bytes(blob)),
        main_opts={"backend": "blob", "arch": "amd64", "base_addr": base, "entry_point": base},
        auto_load_libs=False,
    )


# pylint: disable=missing-class-docstring, no-self-use
class TestLowGlobalRefs(unittest.TestCase):
    def test_low_mapped_global_address_stored(self):
        # image at 0x10000 (like a kernel driver): g_20010 = &g_20000, but 0x20100 has no data access
        code = bytes.fromhex(
            "c704250000020041000000"  # mov dword [0x20000], 0x41
            "48c704251000020000000200"  # mov qword [0x20010], 0x20000
            "b800010200"  # mov eax, 0x20100
            "c3"
        )
        p = _blob_project(code, 0x10000)
        cfg = p.analyses.CFGFast(function_starts=[0x10000], normalize=True)
        d = p.analyses.Decompiler(p.kb.functions[0x10000], cfg=cfg.model, fail_fast=True)
        text = d.codegen.text
        assert "g_20010 = &g_20000;" in text
        assert "return 0x20100;" in text

    def test_low_mapped_pointer_typed_argument(self):
        # f(char *) gets a reference; g(long) keeps the integer
        code = bytes.fromhex(
            "bf20000200"  # mov edi, 0x20020
            "e8f6000000"  # call 0x10100
            "bf30000200"  # mov edi, 0x20030
            "e8fc000000"  # call 0x10110
            "c3"
        )
        p = _blob_project(code, 0x10000, extra={0x100: b"\xc3", 0x110: b"\xc3"})
        cfg = p.analyses.CFGFast(function_starts=[0x10000, 0x10100, 0x10110], normalize=True)
        for addr, sig in ((0x10100, "void f(char *a);"), (0x10110, "void g(long a);")):
            func = p.kb.functions[addr]
            func.prototype = parse_signature(sig).with_arch(p.arch)
            func.calling_convention = SimCCSystemVAMD64(p.arch)
        d = p.analyses.Decompiler(p.kb.functions[0x10000], cfg=cfg.model, fail_fast=True)
        text = d.codegen.text
        assert "sub_10100(&g_20020);" in text
        assert "sub_10110(0x20030);" in text

    def test_zero_based_image_first_page(self):
        # image at 0: constants in the first page stay integers even with a direct access
        code = bytes.fromhex(
            "c704250008000041000000"  # mov dword [0x800], 0x41
            "48c704251008000000080000"  # mov qword [0x810], 0x800
            "48c704251020000000200000"  # mov qword [0x2010], 0x2000
            "c704250020000042000000"  # mov dword [0x2000], 0x42
            "c3"
        )
        p = _blob_project(code, 0)
        cfg = p.analyses.CFGFast(function_starts=[0], normalize=True)
        d = p.analyses.Decompiler(p.kb.functions[0], cfg=cfg.model, fail_fast=True)
        text = d.codegen.text
        assert "&g_800" not in text
        assert "g_2010 = &g_2000;" in text


if __name__ == "__main__":
    unittest.main()

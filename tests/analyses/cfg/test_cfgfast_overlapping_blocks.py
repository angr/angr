#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""CFGFast._remove_redundant_overlapping_blocks on a crafted blob with alignment nops between functions."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import io
import struct
import unittest

import angr

BLOB_BASE = 0x400000


def _blob() -> bytes:
    b = bytearray()
    b += bytes.fromhex("554889e531c05dc3")  # 0x00 A: push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
    b += bytes.fromhex("0f1f840000000000")  # 0x08 nopl 0(%rax,%rax,1)
    b += bytes.fromhex("554889e5b8010000005dc3")  # 0x10 B
    b += bytes.fromhex("6690") + b"\x90" * 3  # 0x1b xchg ax, ax; nop * 3
    b += b"\xe8" + struct.pack("<i", 0x10 - (0x20 + 5))  # 0x20 C: call B
    b += b"\xc3"
    b += b"\xcc" * 10  # 0x26
    b += b"\x90" * 8  # 0x30 nops, then D
    b += bytes.fromhex("31c0c3")  # 0x38 D: xor eax, eax; ret
    b += b"\x00" * 5
    return bytes(b)


# recorded with the Python implementation (angr 4efdbc573): the linear sweep starts functions at 0x08 and 0x30;
# the leading nops of those blocks are split off (0x30 -> 0x38) or the nop block is shrunk in front of B (0x08)
EXPECTED_NODES = [(0, 8, 0), (8, 8, 8), (16, 11, 16), (27, 5, 27), (32, 5, 32), (37, 1, 32), (48, 8, 48), (56, 3, 56)]
EXPECTED_EDGES = [
    (8, 16, "Ijk_Boring"),
    (27, 32, "Ijk_Boring"),
    (32, 16, "Ijk_Call"),
    (32, 37, "Ijk_FakeRet"),
    (48, 56, "Ijk_Boring"),
]
EXPECTED_FUNCS = [(0, [0]), (8, [8]), (16, [16]), (27, [27]), (32, [32, 37]), (48, [48]), (56, [56])]


class TestOverlappingBlocks(unittest.TestCase):
    def test_alignment_nops_complete_scan(self):
        proj = angr.Project(
            io.BytesIO(_blob()),
            main_opts={"backend": "blob", "arch": "AMD64", "base_addr": BLOB_BASE, "entry_point": BLOB_BASE + 0x20},
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFGFast(normalize=False, force_complete_scan=True)
        nodes = sorted(
            (n.addr - BLOB_BASE, n.size, None if n.function_address is None else n.function_address - BLOB_BASE)
            for n in cfg.graph.nodes()
        )
        edges = sorted(
            (s.addr - BLOB_BASE, d.addr - BLOB_BASE, data["jumpkind"]) for s, d, data in cfg.graph.edges(data=True)
        )
        funcs = sorted(
            (f.addr - BLOB_BASE, sorted(b - BLOB_BASE for b in f.block_addrs)) for f in proj.kb.functions.values()
        )
        assert nodes == EXPECTED_NODES
        assert edges == EXPECTED_EDGES
        assert funcs == EXPECTED_FUNCS


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""CFGFast._remove_redundant_overlapping_blocks on a crafted blob with alignment nops between functions."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import io
import random
import struct
import unittest

import archinfo
import capstone
import pyvex

import angr
from angr.analyses.cfg.cfg_base import CFGBase
from angr.rustylib.cfg_post import X86_NOPS, x86_all_nops, x86_leading_nop_len

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


# instruction snippets mixed with the nops of X86_NOPS: effectful instructions, nop look-alikes, cut-off nops
_SNIPPETS = [
    bytes.fromhex(h)
    for h in (
        "55",
        "4157",
        "4889e5",
        "31c0",
        "c3",
        "cc",
        "e800000000",
        "eb00",
        "e900000000",
        "f30f1efa",
        "488d7600",
        "8d7600",
        "8d742600",
        "89ff",
        "4889ff",
        "88c0",
        "8bc0",
        "87db",
        "4887db",
        "4190",
        "f390",
        "d9d0",
        "0f0b",
        "0fb9c0",
        "0fffc0",
        "0f0d00",
        "0f1840",
        "0f19c0",
        "0fb6c0",
        "c5f877",
        "b801000000",
        "c7c001000000",
        "a1",
        "66",
        "0f1f",
        "0f1f44",
        "660f1f8400",
        "2e",
        "06",
        "f4",
        "9b",
        "0f05",
        "7400",
        "ff25",
        "488d3d00000000",
    )
]


def _random_code(rng: random.Random) -> bytes:
    parts = [rng.choice(X86_NOPS) if rng.random() < 0.6 else rng.choice(_SNIPPETS) for _ in range(rng.randint(1, 6))]
    return b"".join(parts) + bytes(rng.randrange(256) for _ in range(4))


class TestX86NopClassification(unittest.TestCase):
    """The byte-level shortcuts of the overlap pass agree with lifting and disassembling."""

    def test_nop_table_agrees_with_pyvex_and_capstone(self):
        for arch, mode in ((archinfo.ArchX86(), capstone.CS_MODE_32), (archinfo.ArchAMD64(), capstone.CS_MODE_64)):
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)
            for nop in X86_NOPS:
                irsb = pyvex.lift(nop + b"\x55", 0x1000, arch, max_bytes=len(nop), opt_level=1, skip_stmts=True)
                assert irsb.size == len(nop) and irsb.is_noop_block, (arch.name, nop.hex())
                assert [(i.mnemonic, i.size) for i in md.disasm(nop, 0x1000)] == [("nop", len(nop))]

    def test_byte_shortcuts_agree_with_lifting(self):
        rng = random.Random(0x5EED)
        codes = [_random_code(rng) for _ in range(300)]
        blob = b"".join(c.ljust(64, b"\xc3") for c in codes)
        for arch_name in ("AMD64", "X86"):
            proj = angr.Project(
                io.BytesIO(blob),
                main_opts={"backend": "blob", "arch": arch_name, "base_addr": BLOB_BASE, "entry_point": BLOB_BASE},
                auto_load_libs=False,
            )
            is_64 = arch_name == "AMD64"
            for idx, code in enumerate(codes):
                addr = BLOB_BASE + idx * 64
                padded = code.ljust(64, b"\xc3")
                for max_size in (1, 3, 7, 16):
                    expected = x86_leading_nop_len(padded, max_size, is_64)
                    if expected is None:
                        continue
                    block = proj.factory.block(addr, size=max_size, opt_level=1, cross_insn_opt=False)
                    if CFGBase._is_noop_block(proj.arch, block):
                        nop_length = block.size
                    else:
                        insns = block.capstone.insns
                        nop_length = CFGBase._get_nop_length(insns) if insns else 0
                    assert nop_length == expected, (arch_name, code.hex(), max_size)
                for n in (1, 2, 5, 9, len(code)):
                    expected = x86_all_nops(padded[:n], is_64)
                    if expected is None:
                        continue
                    insns = proj.factory.fresh_block(addr, n).capstone.insns
                    assert (bool(insns) and all(CFGBase._is_noop_insn(i) for i in insns)) == expected, (
                        arch_name,
                        padded[:n].hex(),
                    )


if __name__ == "__main__":
    unittest.main()

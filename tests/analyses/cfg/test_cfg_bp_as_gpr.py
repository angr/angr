#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os.path
import types
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from angr.rustylib.cfg_block import bp_as_gpr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _capstone_verdict(code: bytes, arch: str) -> tuple[bool, bytes, list[int]]:
    """CFGFast._bp_as_gpr_by_capstone on the block at the start of `code`, its bytes and VEX instruction addresses."""
    proj = angr.load_shellcode(code, arch=arch, load_address=0)
    lift = lambda addr, size: proj.factory.block(addr, size=size, opt_level=1, cross_insn_opt=False)
    fake = types.SimpleNamespace(project=proj, _lift=lift)
    # CFG nodes are as large as their VEX block
    size = lift(0, len(code)).vex.size
    block = lift(0, size)
    return CFGFast._bp_as_gpr_by_capstone(fake, 0, size), block.bytes[:size], list(block.instruction_addrs)


class TestBpAsGpr(unittest.TestCase):
    def test_decoder_agrees_with_capstone(self):
        cases = [
            # push rbp; mov rbp, rsp; sub rsp, 0x20; call rel32
            ("amd64", "554889e54883ec20e800000000", False),
            # mov [rsp+8], rbx; push rdi; lea rbp, [rsp-0x5f]; sub rsp, 0xa0
            ("amd64", "48895c240857488d6c24a14881eca0000000", False),
            # mov ebp, esp is not rbp, rsp; mov r13, rsp; lea r13, [rsp+8]; ret
            ("amd64", "89e54989e54c8d6c2408c3", True),
            # mov rax, gs:[0x30]; movaps [rsp+0x10], xmm6; mov rbp, rsp
            ("amd64", "65488b0425300000000f297424104889e5", False),
            # endbr64; nop word [rax+rax]; rep stosq (VEX ends the block)
            ("amd64", "f30f1efa660f1f440000f348ab", True),
            # push ebp; mov ebp, esp; push -1
            ("x86", "558bec6aff", False),
            # mov eax, fs:[0]; lea ebp, [esp-0x10]
            ("x86", "64a1000000008d6c24f0", False),
            # lea ebp, [eax+eax*2]; mov eax, [0x1000]; ret 4
            ("x86", "8d2c40a100100000c20400", True),
        ]
        for arch, code, expected in cases:
            verdict, b, insn_addrs = _capstone_verdict(bytes.fromhex(code), arch)
            assert verdict is expected, code
            assert bp_as_gpr(b, 0, insn_addrs, arch == "amd64") is expected, code

    def test_decoder_is_unsure(self):
        # an x87 instruction before the frame setup, an instruction boundary VEX does not report, a 16-bit operand
        assert bp_as_gpr(bytes.fromhex("d9ee8bec"), 0, [0, 2], False) is None
        assert bp_as_gpr(bytes.fromhex("554889e5"), 0, [0, 2], True) is None
        assert bp_as_gpr(bytes.fromhex("66678bec"), 0, [0], False) is None

    def test_scan_shadow(self):
        # the Rust scan decides every block itself; in shadow mode capstone is asked too and must agree
        path = os.path.join(test_location, "x86_64", "windows", "fastfail.exe")
        cfg = angr.Project(path, auto_load_libs=False).analyses.CFGFast(normalize=True)
        assert cfg._block_scan_stats.get("bp_as_gpr:rust", 0) > 0
        with mock.patch.object(CFGFast, "_rust_bp_as_gpr_shadow", True):
            cfg2 = angr.Project(path, auto_load_libs=False).analyses.CFGFast(normalize=True)
        stats = cfg2._block_scan_stats
        assert stats.get("bp_as_gpr:shadow_same:decoder", 0) > 0
        assert not [k for k in stats if k.startswith("bp_as_gpr:shadow_mismatch")]
        info = lambda c: {f.addr: f.info.get("bp_as_gpr") for f in c.kb.functions.values()}
        assert info(cfg) == info(cfg2)


if __name__ == "__main__":
    unittest.main()

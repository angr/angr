#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os.path
import struct
import unittest

import archinfo

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

SH4 = "SuperH4:LE:32:default"


class TestPcodeConstResolver(unittest.TestCase):
    def test_resolving_sh4_literal_pool_call_in_shellcode(self):
        # SuperH reaches most of its calls through a register loaded from the literal pool that follows the code.
        base = 0x400000
        code = b"".join(
            [
                b"\x02\xd1",  # 400000  mov.l @(2,pc), r1    ; r1 <- the word at 0x40000c
                b"\x0b\x41",  # 400002  jsr @r1
                b"\x09\x00",  # 400004  nop                  ; delay slot
                b"\x0b\x00",  # 400006  rts
                b"\x09\x00",  # 400008  nop                  ; delay slot
                b"\x09\x00",  # 40000a  nop                  ; padding to align the literal pool
                struct.pack("<I", base + 0x10),  # 40000c  the literal pool
                b"\x0b\x00",  # 400010  rts                  ; the callee
                b"\x09\x00",  # 400012  nop                  ; delay slot
            ]
        )
        proj = angr.load_shellcode(code, arch=archinfo.ArchPcode(SH4), load_address=base, start_offset=0)

        cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)

        node = cfg.model.get_any_node(base)
        assert node is not None
        assert [succ.addr for succ in cfg.model.get_successors(node)] == [base + 0x10]
        assert cfg.functions.contains_addr(base + 0x10)
        assert not cfg.indirect_jumps

    def test_resolving_sh4_literal_pool_tail_jump_in_shellcode(self):
        # A tail call reaches the same register through BRANCHIND rather than CALLIND, and becomes a jump target.
        base = 0x400000
        code = b"".join(
            [
                b"\x02\xd1",  # 400000  mov.l @(2,pc), r1    ; r1 <- the word at 0x40000c
                b"\x2b\x41",  # 400002  jmp @r1
                b"\x09\x00",  # 400004  nop                  ; delay slot
                b"\x09\x00",  # 400006  nop                  ; padding to align the literal pool
                b"\x09\x00",  # 400008  nop
                b"\x09\x00",  # 40000a  nop
                struct.pack("<I", base + 0x10),  # 40000c  the literal pool
                b"\x0b\x00",  # 400010  rts                  ; the callee
                b"\x09\x00",  # 400012  nop                  ; delay slot
            ]
        )
        proj = angr.load_shellcode(code, arch=archinfo.ArchPcode(SH4), load_address=base, start_offset=0)

        cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)

        node = cfg.model.get_any_node(base)
        assert node is not None
        assert [succ.addr for succ in cfg.model.get_successors(node)] == [base + 0x10]
        assert not cfg.indirect_jumps

    def test_sh4_call_after_a_store_the_block_cannot_place(self):
        # The literal pool sits in writable memory here, so a store to an address the fold cannot place may have
        # changed it. The same block without the store resolves, which is what makes the store the reason.
        base = 0x400000
        tail = b"".join(
            [
                b"\x02\xd1",  # 400002  mov.l @(2,pc), r1    ; r1 <- the word at 0x40000c
                b"\x0b\x41",  # 400004  jsr @r1
                b"\x09\x00",  # 400006  nop                  ; delay slot
                b"\x0b\x00",  # 400008  rts
                b"\x09\x00",  # 40000a  nop                  ; delay slot
                struct.pack("<I", base + 0x10),  # 40000c  the literal pool
                b"\x0b\x00",  # 400010  rts                  ; the callee
                b"\x09\x00",  # 400012  nop                  ; delay slot
            ]
        )
        store = b"\x62\x2f"  # 400000  mov.l r6,@r15
        nop = b"\x09\x00"  # 400000  nop

        def call_target(first_instruction):
            proj = angr.load_shellcode(
                first_instruction + tail, arch=archinfo.ArchPcode(SH4), load_address=base, start_offset=0
            )
            cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)
            node = cfg.model.get_any_node(base)
            assert node is not None
            unresolvable = proj.loader.extern_object.get_pseudo_addr("UnresolvableCallTarget")
            return [(None if succ.addr == unresolvable else succ.addr) for succ in cfg.model.get_successors(node)]

        assert call_target(nop) == [base + 0x10]
        assert call_target(store) == [None]

    def test_sh4_call_through_a_register_the_block_does_not_define(self):
        # The target arrives in r4 from the caller, so folding the block on its own cannot produce it and the call
        # must stay unresolved instead of picking up whatever r4 last held.
        base = 0x400000
        code = b"".join(
            [
                b"\x0b\x44",  # 400000  jsr @r4
                b"\x09\x00",  # 400002  nop                  ; delay slot
                b"\x0b\x00",  # 400004  rts
                b"\x09\x00",  # 400006  nop                  ; delay slot
            ]
        )
        proj = angr.load_shellcode(code, arch=archinfo.ArchPcode(SH4), load_address=base, start_offset=0)

        cfg = proj.analyses.CFGFast(normalize=True, resolve_indirect_jumps=True)

        assert base in cfg.indirect_jumps
        node = cfg.model.get_any_node(base)
        assert node is not None
        assert [succ.addr for succ in cfg.model.get_successors(node)] == [
            proj.loader.extern_object.get_pseudo_addr("UnresolvableCallTarget")
        ]

    def test_resolving_sh4_literal_pool_call_in_binary(self):
        bin_path = os.path.join(test_location, "sh4", "test-instr_sh4")
        proj = angr.Project(
            bin_path,
            auto_load_libs=False,
            use_sim_procedures=False,
            main_opts={"backend": "elf", "arch": archinfo.ArchPcode(SH4)},
        )
        cfg = proj.analyses.CFGFast(
            normalize=True,
            resolve_indirect_jumps=True,
            regions=[(0x400458, 0x400474)],
            function_starts=[0x400458],
            start_at_entry=False,
        )

        # _start loads __libc_start_main (0x400638) and abort (0x404fe0) out of its literal pool and calls both
        # through r1.
        start = cfg.functions[0x400458]
        assert {start.get_call_target(site) for site in start.get_call_sites()} == {0x400638, 0x404FE0}


if __name__ == "__main__":
    unittest.main()

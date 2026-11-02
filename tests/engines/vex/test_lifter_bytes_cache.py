#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.engines.vex"  # pylint:disable=redefined-builtin

import unittest

import pyvex

import angr
from angr.knowledge_plugins.cfg.cfg_node import CFGENode

BASE = 0x401000
# mov rax, 1; add rax, rbx; cmp rax, 2; je +2; nop; nop; ret
CODE = b"\x48\xc7\xc0\x01\x00\x00\x00\x48\x01\xd8\x48\x83\xf8\x02\x74\x02\x90\x90\xc3"


def _project(selfmodifying_code):
    return angr.load_shellcode(CODE, "AMD64", load_address=BASE, selfmodifying_code=selfmodifying_code)


class TestLifterBytesCache(unittest.TestCase):
    def test_hit_on_identical_bytes(self):
        for smc in (False, True):
            p = _project(smc)
            eng = p.factory.default_engine
            assert eng._use_cache, "the bytes-keyed cache is sound under self-modifying code"
            s1 = p.factory.blank_state(addr=BASE)
            s2 = p.factory.blank_state(addr=BASE)
            a = eng.lift_vex(addr=BASE, state=s1)
            assert eng.lift_vex(addr=BASE, state=s1) is a
            assert eng.lift_vex(addr=BASE, state=s2) is a  # same bytes in another state
            assert a.size == 16
            assert eng._block_cache_hits == 2 and eng._block_cache_misses == 1

    def test_miss_after_bytes_change(self):
        for smc in (False, True):
            p = _project(smc)
            eng = p.factory.default_engine
            s = p.factory.blank_state(addr=BASE)
            a = eng.lift_vex(addr=BASE, state=s)

            s.memory.store(BASE, b"\x90")  # the first instruction becomes a nop
            b = eng.lift_vex(addr=BASE, state=s)
            assert b is not a
            assert b.statements[0].len == 1 and a.statements[0].len == 7
            assert eng.lift_vex(addr=BASE, state=s) is b

            s.memory.store(BASE + 14, b"\x90\x90")  # je +2 -> nops: the block now runs on to the ret
            c = eng.lift_vex(addr=BASE, state=s)
            assert c is not b and c.jumpkind == "Ijk_Ret" and c.size == len(CODE)

            s.memory.store(BASE, CODE[:1])
            s.memory.store(BASE + 14, CODE[14:16])
            assert eng.lift_vex(addr=BASE, state=s) is a  # original bytes, original IRSB

    def test_engine_step_sees_patched_bytes(self):
        p = _project(False)
        s = p.factory.blank_state(addr=BASE)
        irsb = p.factory.successors(s).artifacts["irsb"]
        assert p.factory.successors(s).artifacts["irsb"] is irsb
        s.memory.store(BASE + 14, b"\x90\x90")  # je +2 -> two nops
        patched = p.factory.successors(s).artifacts["irsb"]
        assert patched is not irsb
        assert irsb.jumpkind == "Ijk_Boring" and patched.jumpkind == "Ijk_Ret"
        assert not any(isinstance(st, pyvex.stmt.Exit) for st in patched.statements)

    def test_loader_memory_change_misses(self):
        p = _project(False)
        eng = p.factory.default_engine
        a = p.factory.block(BASE).vex
        assert p.factory.block(BASE).vex is a
        p.loader.memory.store(BASE, b"\x90")
        b = p.factory.block(BASE).vex
        assert b is not a and b.statements[0].len == 1
        assert eng._block_cache_misses == 2

    def test_thumb_lookbehind_bytes_are_keyed(self):
        # libVEX inspects the 9 halfwords before a thumb block for an IT instruction once >= 18 bytes precede it
        nop, itttt_eq = b"\x00\xbf", b"\x01\xbf"
        code = nop * 9 + b"\x01\x21" + b"\x70\x47"  # 9x nop; movs r1, #1; bx lr
        p = angr.load_shellcode(code, "ARMEL", load_address=BASE)
        eng = p.factory.default_engine
        state = p.factory.blank_state(addr=BASE + 19)
        a = p.factory.block(BASE + 19).vex  # offset exactly 18 into the loader backer
        sa = eng.lift_vex(addr=BASE + 19, state=state)
        assert str(sa) == str(a)  # state and loader lifts see the same look-behind

        # an IT guarding 4 insns 8 halfwords back may reach this block
        p.loader.memory.store(BASE + 2, itttt_eq)
        state.memory.store(BASE + 2, itttt_eq)
        b = p.factory.block(BASE + 19).vex
        assert b is not a and str(b) != str(a)  # the block may now be IT-guarded
        sb = eng.lift_vex(addr=BASE + 19, state=state)
        assert sb is not sa and str(sb) == str(b)

    def test_consumer_mutation_does_not_leak(self):
        p = _project(False)
        eng = p.factory.default_engine
        s = p.factory.blank_state(addr=BASE)
        a = eng.lift_vex(addr=BASE, state=s)
        n_stmts, jumpkind = len(a.statements), a.jumpkind

        node = CFGENode(BASE, a.size, None, irsb=a, instruction_addrs=list(a.instruction_addresses))
        assert node.irsb is not a
        node.irsb.statements = node.irsb.statements[:1]
        node.irsb.jumpkind = "Ijk_Ret"
        node.irsb.next = pyvex.expr.Const(pyvex.const.U64(0))

        again = eng.lift_vex(addr=BASE, state=s)
        assert again is a
        assert len(a.statements) == n_stmts and a.jumpkind == jumpkind
        assert p.factory.successors(s).artifacts["irsb"] is a


if __name__ == "__main__":
    unittest.main()

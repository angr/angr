#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import itertools
import unittest

import networkx

import angr
from angr.ailment.block import Block
from angr.ailment.expression import (
    Call,
    Const,
    Load,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import ConditionalJump, Jump, Return, SideEffectStatement, Store
from angr.analyses.decompiler.dead_global_stores import CallGlobalReads, find_dead_global_stores

G = 0x601000
_ids = itertools.count(100)


def _c(value: int, bits: int = 64) -> Const:
    return Const(next(_ids), value, bits)


def _addr(addr):
    return _c(addr) if isinstance(addr, int) else addr


def _store(idx: int, addr, value: int = 1, size: int = 4) -> Store:
    return Store(idx, _addr(addr), _c(value, size * 8), size, "Iend_LE", ins_addr=idx)


def _load(addr, size: int = 4) -> Load:
    return Load(next(_ids), _addr(addr), size, "Iend_LE")


def _ret(idx: int, *exprs) -> Return:
    return Return(idx, list(exprs), ins_addr=idx)


def _single(*stmts, call_reads=None) -> set[int]:
    graph = networkx.DiGraph()
    graph.add_node(Block(0x400000, 1, statements=list(stmts)))
    return find_dead_global_stores(graph, None, call_reads).get((0x400000, 0), set())


def _call(target, *args) -> SideEffectStatement:
    call = Call(next(_ids), _addr(target) if isinstance(target, int) else target, args=list(args), bits=32)
    return SideEffectStatement(next(_ids), call, ins_addr=1)


FMT, PRINTF = 0x400100, 0x400050


def _lib_reads() -> CallGlobalReads:
    proj = angr.load_shellcode(b"\xc3" * 0x100 + b"%d\x00", arch="amd64", load_address=0x400000)
    proj.hook(PRINTF, angr.SIM_PROCEDURES["libc"]["printf"]())
    return CallGlobalReads(proj)


class TestDeadGlobalStores(unittest.TestCase):
    def test_store_without_reads_is_dead(self):
        assert _single(_store(0, G), _ret(1)) == {0}

    def test_partial_overlapping_load_keeps_store(self):
        assert _single(_store(0, G), _store(1, G + 4), _ret(2, _load(G + 3, 2))) == set()
        assert _single(_store(0, G), _ret(1, _load(G + 4, 1))) == {0}

    def test_overwritten_store_is_dead(self):
        assert _single(_store(0, G), _store(1, G, 2), _ret(2, _load(G))) == {0}
        # a narrower overwrite leaves the other bytes live
        assert _single(_store(0, G), _store(1, G, 2, size=1), _ret(2, _load(G))) == set()

    def test_calls_read_every_global(self):
        call = Call(next(_ids), _c(0x400500), args=[], bits=32, ins_addr=1)
        assert _single(_store(0, G), _ret(1, call)) == set()
        # the call happens before the store
        assert _single(Store(0, _c(G), call, 4, "Iend_LE", ins_addr=0), _ret(1)) == set()

    def test_unknown_pointer_reads_every_global(self):
        ptr = VirtualVariable(next(_ids), 1, 64, VirtualVariableCategory.REGISTER, oident=16)
        assert _single(_store(0, G), _ret(1, _load(ptr))) == set()
        assert _single(_store(0, G), _ret(1, _load(StackBaseOffset(next(_ids), 64, -8)))) == {0}

    def test_cross_block_and_loops(self):
        head = Block(0x1000, 1, statements=[_store(0, G)])
        body = Block(
            0x1010,
            1,
            statements=[ConditionalJump(1, _load(G, 1), _c(0x1010), _c(0x1020), ins_addr=1)],
        )
        tail = Block(0x1020, 1, statements=[_store(2, G + 8), _ret(3)])
        graph = networkx.DiGraph([(head, body), (body, body), (body, tail)])
        assert find_dead_global_stores(graph) == {(0x1020, 0): {0}}

    def test_leaving_without_return_reads_every_global(self):
        assert _single(_store(0, G), Jump(1, _c(0x500000), ins_addr=1)) == set()
        block = Block(0x1000, 1, statements=[_store(0, G), Jump(1, _c(0x500000), ins_addr=1)])
        succ = Block(0x1010, 1, statements=[_ret(2)])
        assert find_dead_global_stores(networkx.DiGraph([(block, succ)])) == {}


class TestCallGlobalReads(unittest.TestCase):
    def test_library_call_reads_only_its_strings(self):
        reads = _lib_reads()
        printf = _call(PRINTF, _c(FMT), _c(5, 32))
        assert _single(_store(0, G), printf, _ret(2), call_reads=reads) == {0}
        # printf reads its format string
        assert _single(_store(0, FMT + 1, size=1), printf, _ret(2), call_reads=reads) == set()
        # a synthesized strncpy reads its source string
        strncpy = _call("strncpy", StackBaseOffset(next(_ids), 64, -16), _c(FMT), _c(2))
        assert _single(_store(0, G), strncpy, _ret(2), call_reads=reads) == {0}

    def test_calls_that_may_read_any_global(self):
        reads = _lib_reads()
        # a variadic argument the format string asks for is missing
        assert _single(_store(0, G), _call(PRINTF, _c(FMT)), _ret(2), call_reads=reads) == set()
        # not a library callee
        assert _single(_store(0, G), _call(0x400060, _c(FMT), _c(5, 32)), _ret(2), call_reads=reads) == set()
        # a pointer of unknown provenance
        ptr = VirtualVariable(next(_ids), 1, 64, VirtualVariableCategory.REGISTER, oident=16)
        assert _single(_store(0, G), _call("strncpy", ptr, ptr, _c(2)), _ret(2), call_reads=reads) == set()

    def test_discarded_atomic_on_global(self):
        def cas():
            return _call("InterlockedCompareExchange", _c(G), _c(1, 32), _c(0, 32))

        assert _single(cas(), _ret(1)) == {0}
        assert _single(cas(), _ret(1, _load(G))) == set()
        # the atomic reads the bytes it compares
        assert _single(_store(0, G), cas(), _ret(2)) == {1}


class TestDeadGlobalStoresDecompiler(unittest.TestCase):
    # mov dword [0x601000], 1; mov dword [0x601004], 2; movzx eax, byte [0x601001]; ret
    CODE = (
        bytes.fromhex("c7042500106000" "01000000")
        + bytes.fromhex("c7042504106000" "02000000")
        + bytes.fromhex("0fb6042501106000")
        + b"\xc3"
    )

    def _decompile(self, flag: bool) -> str:
        proj = angr.load_shellcode(self.CODE, arch="amd64", load_address=0x400000)
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000])
        dec = proj.analyses.Decompiler(
            proj.kb.functions[0x400000], cfg=cfg.model, allow_global_dead_ass_elim=flag, fail_fast=True
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_flag_removes_only_unread_store(self):
        text = self._decompile(True)
        assert "g_601000.field_0 = 1;" in text
        assert "g_601004" not in text

    def test_flag_off_keeps_stores(self):
        text = self._decompile(False)
        assert "g_601004 = 2;" in text


if __name__ == "__main__":
    unittest.main()

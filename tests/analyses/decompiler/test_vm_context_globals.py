#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import itertools
import struct
import unittest

import networkx

import angr
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Load,
    StackBaseOffset,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump, Return, SideEffectStatement, Store
from angr.analyses.decompiler.dead_global_stores import find_dead_global_stores
from angr.analyses.decompiler.vm_context_globals import (
    VMContext,
    VMContextLayout,
    analyze_vm_context,
    find_vm_context_layout,
    forward_vm_context_stores,
    spin_lock_words,
)

# the protector's section, the VM context inside it, its lock word, and a program global outside it
SECTION = (0x500000, 0x510000)
CTX = 0x508000
LOCK = 0x508040
PROG = 0x401000
LAYOUT = VMContextLayout([SECTION], [(CTX, CTX + 0x80)])
_ids = itertools.count(1000)


def _c(value: int, bits: int = 64) -> Const:
    return Const(next(_ids), value, bits)


def _vvar(varid: int, bits: int = 64) -> VirtualVariable:
    return VirtualVariable(next(_ids), varid, bits, VirtualVariableCategory.REGISTER, oident=16)


def _store(addr, data, size: int = 8) -> Store:
    return Store(next(_ids), _c(addr) if isinstance(addr, int) else addr, data, size, "Iend_LE", ins_addr=1)


def _load(addr, size: int = 8) -> Load:
    return Load(next(_ids), _c(addr) if isinstance(addr, int) else addr, size, "Iend_LE")


def _def(varid: int, src) -> Assignment:
    return Assignment(next(_ids), _vvar(varid, src.bits), src, ins_addr=1)


def _call(target, *args) -> SideEffectStatement:
    target = _c(target) if isinstance(target, int) else target
    return SideEffectStatement(next(_ids), Call(next(_ids), target, args=list(args), bits=64), ins_addr=1)


def _acquire() -> SideEffectStatement:
    return _call("InterlockedCompareExchange", _c(LOCK), _c(1, 32), _c(0, 32))


def _ret(*exprs) -> Return:
    return Return(next(_ids), list(exprs), ins_addr=1)


def _graph(*blocks, edges=()) -> networkx.DiGraph:
    graph = networkx.DiGraph()
    graph.add_nodes_from(blocks)
    graph.add_edges_from(edges)
    return graph


def _forward(graph, layout=LAYOUT) -> int:
    return forward_vm_context_stores(graph, layout, Manager(), entry_addr=0x1000)


def _src(block: Block, idx: int):
    return block.statements[idx].src


class TestForwarding(unittest.TestCase):
    def test_store_reaches_load(self):
        block = Block(0x1000, 1, statements=[_store(CTX, _vvar(1)), _def(2, _load(CTX)), _ret(_vvar(2))])
        assert _forward(_graph(block)) == 1
        assert isinstance(_src(block, 1), VirtualVariable) and _src(block, 1).varid == 1

    def test_narrow_and_composed_loads(self):
        block = Block(
            0x1000,
            1,
            statements=[
                _store(CTX, _vvar(1)),
                _def(2, _load(CTX, 4)),
                _store(CTX + 8, _vvar(3, 32), 4),
                _store(CTX + 12, _c(0, 32), 4),
                _def(4, _load(CTX + 8)),
                _ret(),
            ],
        )
        assert _forward(_graph(block)) == 2
        assert not isinstance(_src(block, 1), Load) and _src(block, 1).bits == 32
        assert not isinstance(_src(block, 4), Load) and _src(block, 4).bits == 64

    def test_program_global_is_untouched(self):
        block = Block(0x1000, 1, statements=[_store(PROG, _vvar(1)), _def(2, _load(PROG)), _ret(_vvar(2))])
        assert _forward(_graph(block)) == 0
        assert isinstance(_src(block, 1), Load)

    def test_merge_of_equal_and_different_values(self):
        def run(value_a, value_b):
            head = Block(0x1000, 1, statements=[ConditionalJump(next(_ids), _vvar(9, 1), _c(0x1010), _c(0x1020))])
            left = Block(0x1010, 1, statements=[_store(CTX, value_a)])
            right = Block(0x1020, 1, statements=[_store(CTX, value_b)])
            tail = Block(0x1030, 1, statements=[_def(2, _load(CTX)), _ret(_vvar(2))])
            graph = _graph(head, left, right, tail, edges=[(head, left), (head, right), (left, tail), (right, tail)])
            return _forward(graph), tail

        count, tail = run(_vvar(1), _vvar(1))
        assert count == 1 and isinstance(_src(tail, 0), VirtualVariable)
        count, tail = run(_vvar(1), _vvar(3))
        assert count == 0 and isinstance(_src(tail, 0), Load)

    def test_loop_carried_value_is_not_forwarded(self):
        entry = Block(0x1000, 1, statements=[_store(CTX, _vvar(1))])
        head = Block(0x1010, 1, statements=[_def(2, _load(CTX))])
        body = Block(0x1020, 1, statements=[_def(3, _vvar(2)), _store(CTX, _vvar(3))])
        graph = _graph(entry, head, body, edges=[(entry, head), (head, body), (body, head)])
        assert _forward(graph) == 0

    def test_aliasing_store_blocks(self):
        # a pointer derived from a context address may write any context byte
        ptr = _vvar(5)
        block = Block(
            0x1000,
            1,
            statements=[
                _def(5, _c(CTX + 0x10)),
                _store(CTX, _vvar(1)),
                _store(ptr, _vvar(6)),
                _def(2, _load(CTX)),
                _ret(),
            ],
        )
        assert _forward(_graph(block)) == 0
        # a stack pointer cannot
        block = Block(
            0x1000,
            1,
            statements=[_store(CTX, _vvar(1)), _store(StackBaseOffset(next(_ids), 64, -8), _vvar(6)), _def(2, _load(CTX))],
        )
        assert _forward(_graph(block)) == 1

    def test_calls(self):
        def run(*between):
            block = Block(
                0x1000, 1, statements=[_store(CTX, _vvar(1)), *between, _def(2, _load(CTX)), _ret(_vvar(2))]
            )
            return _forward(_graph(block))

        # a callee handed no context address cannot reach the context; the VM relies on it surviving the call
        assert run(_call(0x400500, StackBaseOffset(next(_ids), 64, -16))) == 1
        # one handed a context address may write it
        assert run(_call(0x400500, _c(CTX))) == 0
        # once a context address escapes into program memory, any callee may
        assert run(_store(PROG, _c(CTX + 8)), _call(0x400500)) == 0

    def test_lock_atomic_writes_only_the_lock(self):
        block = Block(
            0x1000,
            1,
            statements=[
                _store(CTX, _vvar(1)),
                _store(LOCK, _c(0, 32), 4),
                _acquire(),
                _def(2, _load(CTX)),
                _def(3, _load(LOCK, 4)),
                _ret(),
            ],
        )
        assert _forward(_graph(block)) == 1
        assert isinstance(_src(block, 3), VirtualVariable)
        assert isinstance(_src(block, 4), Load)

    def test_block_copies_are_not_specialized(self):
        entry = Block(0x1000, 1, statements=[ConditionalJump(next(_ids), _vvar(9, 1), _c(0x1010), _c(0x1020))])
        left = Block(0x1010, 1, statements=[_store(CTX, _c(0, 8), 1)])
        right = Block(0x1020, 1, statements=[_store(CTX, _c(1, 8), 1)])
        copy0 = Block(0x1030, 1, statements=[_def(2, _load(CTX, 1))], idx=0)
        copy1 = Block(0x1030, 1, statements=[_def(2, _load(CTX, 1))], idx=1)
        graph = _graph(
            entry, left, right, copy0, copy1, edges=[(entry, left), (entry, right), (left, copy0), (right, copy1)]
        )
        assert _forward(graph) == 0


class TestPrivateContextLiveness(unittest.TestCase):
    def _dead(self, *between, layout=LAYOUT):
        block = Block(0x1000, 1, statements=[_store(CTX, _vvar(1)), *between, _ret()])
        graph = _graph(block)
        return find_dead_global_stores(graph, None, None, VMContext.analyze(graph, layout)).get((0x1000, 0), set())

    def test_call_does_not_read_private_context(self):
        assert self._dead(_call(0x400500)) == {0}
        assert self._dead(_call(0x400500), layout=VMContextLayout([], [])) == set()

    def test_call_handed_a_context_address_reads_it(self):
        assert self._dead(_call(0x400500, _c(CTX))) == set()
        assert self._dead(_store(PROG, _c(CTX)), _call(0x400500)) == set()

    def test_lock_operations_are_removed(self):
        stmts = [_acquire(), _store(CTX, _vvar(1)), _call(0x400500), _store(LOCK, _c(0, 32), 4), _acquire(), _ret()]
        graph = _graph(Block(0x1000, 1, statements=stmts))
        dead = find_dead_global_stores(graph, None, None, VMContext.analyze(graph, LAYOUT))
        assert dead == {(0x1000, 0): {0, 1, 3, 4}}


def _op(op: str, a, b):
    return BinaryOp(next(_ids), op, [a, b], False, bits=a.bits)


class TestTaintCancellation(unittest.TestCase):
    """A value whose context-derived terms cancel carries no context address."""

    FRAME = StackBaseOffset(None, 64, -0x40)

    def _private(self, *stmts) -> bool:
        graph = _graph(Block(0x1000, 1, statements=[*stmts, _ret()]))
        return analyze_vm_context(graph, LAYOUT).private

    def test_added_and_subtracted_key_cancels(self):
        key = _def(1, _op("Xor", _vvar(9), _c(CTX + 8)))
        enc = _def(2, _op("Sub", self.FRAME, _vvar(1)))
        assert self._private(key, enc, _store(PROG, _op("Add", _vvar(2), _vvar(1))))
        assert not self._private(key, enc, _store(PROG, _vvar(2)))
        assert not self._private(key, enc, _store(PROG, _op("Add", _vvar(2), _op("Mul", _vvar(1), _c(2)))))

    def test_xored_key_cancels(self):
        key = _def(1, _op("Add", _vvar(9), _c(CTX)))
        assert self._private(key, _store(PROG, _op("Xor", _op("Xor", _vvar(8), _vvar(1)), _vvar(1))))
        assert not self._private(key, _store(PROG, _op("Xor", _op("Xor", _vvar(8), _vvar(1)), _vvar(9))))

    def test_context_constants_do_not_fold(self):
        # &ctx + c - c is &ctx, whatever c is
        assert not self._private(_store(PROG, _op("Sub", _op("Add", _c(CTX), _c(0x10000000)), _c(0x10000000))))
        assert self._private(_store(PROG, _op("Sub", _op("Add", _c(CTX), _vvar(9)), _c(CTX))))

    def test_loads_of_one_slot_cancel_only_without_a_write_between(self):
        # the slot holds a context address; two reads of it with nothing written between read the same value
        seed = _store(CTX + 8, _c(CTX))
        first = _def(1, _op("Xor", _load(CTX + 8), _vvar(9)))
        use = _store(PROG, _op("Xor", _vvar(1), _load(CTX + 8)))
        assert self._private(seed, first, use)
        assert not self._private(seed, first, _store(CTX + 8, _vvar(7)), use)
        # a pointer that may carry a context address may write the slot
        assert not self._private(seed, first, _def(5, _c(CTX + 0x10)), _store(_vvar(5), _vvar(7)), use)

    def test_lock_and_context_stores_die_through_cancelled_pointers(self):
        key = _def(1, _op("Xor", _vvar(9), _c(CTX + 8)))
        frame_load = _def(3, _load(_op("Xor", _op("Xor", _vvar(8), _vvar(1)), _vvar(1))))
        stmts = [_acquire(), _store(CTX, _vvar(2)), key, frame_load, _ret(_vvar(3))]
        graph = _graph(Block(0x1000, 1, statements=stmts))
        dead = find_dead_global_stores(graph, None, None, analyze_vm_context(graph, LAYOUT))
        assert dead == {(0x1000, 0): {0, 1}}
        # without the cancellation the load may read the context
        stmts[3] = _def(3, _load(_op("Xor", _vvar(8), _vvar(1))))
        graph = _graph(Block(0x1000, 1, statements=stmts))
        assert not find_dead_global_stores(graph, None, None, analyze_vm_context(graph, LAYOUT))


class TestLoadForwarding(unittest.TestCase):
    def test_reload_becomes_the_first_load(self):
        block = Block(0x1000, 1, statements=[_def(1, _load(CTX)), _def(2, _load(CTX)), _ret(_vvar(2))])
        assert _forward(_graph(block)) == 1
        assert isinstance(_src(block, 1), VirtualVariable) and _src(block, 1).varid == 1

    def test_write_between_blocks(self):
        for between in (_store(CTX + 4, _vvar(5), 4), _call(0x400500, _c(CTX))):
            block = Block(0x1000, 1, statements=[_def(1, _load(CTX)), between, _def(2, _load(CTX)), _ret(_vvar(2))])
            assert _forward(_graph(block)) == 0, between

    def test_partial_load_is_not_a_value(self):
        block = Block(0x1000, 1, statements=[_def(1, _load(CTX, 4)), _def(2, _load(CTX)), _ret(_vvar(2))])
        assert _forward(_graph(block)) == 0


def _mini_pe(sections) -> bytes:
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 108, 16)
    table = b"".join(struct.pack("<8sIIIIIIHHI", n, size, rva, 0, 0, 0, 0, 0, 0, ch) for n, rva, size, ch in sections)
    return bytes(dos) + b"PE\0\0" + coff + bytes(opt) + table


# .text (rx), .prot (rwx: lock at 0x402000, context slot at 0x402008), .data (rw: program global at 0x403000)
_IMAGE = _mini_pe(
    [(b".text", 0x1000, 0x1000, 0x60000020), (b".prot", 0x2000, 0x1000, 0xE0000060), (b".data", 0x3000, 0x1000, 0xC0000040)]
)
# xor eax, eax; mov ecx, 1; lock cmpxchg [0x402000], ecx; mov [0x402008], rdi; mov [0x403000], rsi;
# mov rax, [0x402008]; add rax, [0x403000]; ret
_CODE = bytes.fromhex(
    "31c0b901000000f00fb10c2500204000"
    "48893c2508204000"
    "4889342500304000"
    "488b042508204000"
    "4803042500304000"
    "c3"
)


class TestProvenance(unittest.TestCase):
    def _project(self, protector_flags=0xE0000060):
        image = bytearray(_IMAGE.ljust(0x4000, b"\0"))
        struct.pack_into("<I", image, 0x40 + 4 + 20 + 0xF0 + 40 + 36, protector_flags)
        image[0x1000 : 0x1000 + len(_CODE)] = _CODE
        return angr.load_shellcode(bytes(image), arch="amd64", load_address=0x400000)

    def test_layout_needs_a_lock_in_a_writable_executable_section(self):
        lock = Block(0x1000, 1, statements=[_call("InterlockedCompareExchange", _c(0x402000), _c(1, 32), _c(0, 32))])
        access = Block(0x1010, 1, statements=[_store(0x402008, _vvar(1)), _store(0x403000, _vvar(1))])
        graph = _graph(lock, access, edges=[(lock, access)])
        assert spin_lock_words(graph) == {0x402000}
        layout = find_vm_context_layout(self._project(), graph)
        assert layout.sections == [(0x402000, 0x403000)] and layout.regions == [(0x402000, 0x402010)]
        # a lock in a section that is not executable is not the protector's
        assert not find_vm_context_layout(self._project(protector_flags=0xC0000040), graph)
        # no lock, no context
        assert not find_vm_context_layout(self._project(), _graph(access))

    def test_decompiler_drops_vm_context_and_lock(self):
        proj = self._project()
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x401000])
        dec = proj.analyses.Decompiler(
            proj.kb.functions[0x401000],
            cfg=cfg.model,
            allow_global_dead_ass_elim=True,
            vm_deobfuscation=True,
            fail_fast=True,
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "g_402008" not in text and "g_402000" not in text and "Interlocked" not in text
        # the program global keeps its store and its load
        assert text.count("g_403000") >= 3


if __name__ == "__main__":
    unittest.main()

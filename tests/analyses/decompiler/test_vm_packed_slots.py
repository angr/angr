#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import archinfo
import networkx

from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Extract,
    ITE,
    Insert,
    Load,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump
from angr.analyses.decompiler.vm_packed_slots import forward_packed_slot_reads

LE = archinfo.Endness.LE


def _slot(varid, bits=96, offset=-0x20):
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.STACK, oident=offset)


def _reg(varid, bits=32):
    return VirtualVariable(varid, varid, bits, VirtualVariableCategory.REGISTER, oident=16)


def _c(v, bits):
    return Const(None, v, bits)


def _ext(base, bits, byte_off):
    return Extract(None, bits, base, _c(byte_off, 64), LE)


def _ins(base, byte_off, value):
    return Insert(None, base, _c(byte_off, 64), value, LE)


def _ref(v):
    return UnaryOp(None, "Reference", v, bits=64)


def _not(e):
    return UnaryOp(None, "BitwiseNeg", e, bits=e.bits)


def _nor_of_qword(qword):
    # VMProtect's 32-bit NOR: ~hi & ~lo of the qword at vsp+4
    return BinaryOp(None, "And", [_ext(_not(qword), 32, 4), _not(_ext(qword, 32, 0))], False, bits=32)


def _branch(idx, lhs, rhs):
    return ConditionalJump(idx, BinaryOp(None, "CmpNE", [lhs, rhs], False), _c(1, 64), _c(2, 64))


def _graph(*statements):
    block = Block(0x1000, 1, statements=list(statements))
    graph = networkx.DiGraph()
    graph.add_node(block)
    return graph


def _vvar_ids(expr) -> set[int]:
    out = set()

    def walk(e):
        if isinstance(e, VirtualVariable):
            out.add(e.varid)
        for attr in ("operands",):
            for o in getattr(e, attr, None) or ():
                walk(o)
        for attr in ("operand", "base", "value"):
            child = getattr(e, attr, None)
            if child is not None and not isinstance(child, (int, str)) and hasattr(child, "bits"):
                walk(child)

    walk(expr)
    return out


def _condition(graph):
    block = next(iter(graph))
    return block.statements[-1].condition


class TestVMPackedSlots(unittest.TestCase):
    def test_nor_of_a_duplicated_dword_reads_the_dword(self):
        # push x; push x; nor (flags at vsp); push vsp; mov [vsp+4], [vsp+8]; nor  -- cmd_DW's NTSTATUS test
        x = _reg(1)
        v1, v2, v3 = _slot(2), _slot(3), _slot(4)
        graph = _graph(
            Assignment(10, v1, _ins(_ins(_ins(_c(0, 96), 0, _c(0x44, 32)), 4, x), 8, x)),
            Assignment(11, v2, _ins(v1, 0, BinaryOp(None, "Add", [_ref(v1), _c(8, 64)], False, bits=64))),
            Assignment(12, v3, _ins(v2, 4, _ext(v2, 32, 8))),
            _branch(13, _nor_of_qword(_ext(v3, 64, 4)), _c(0, 32)),
        )
        assert forward_packed_slot_reads(graph) > 0
        cond = _condition(graph)
        nor = cond.operands[0]
        assert _vvar_ids(cond) == {x.varid}, f"the condition still reads the slot: {cond}"
        assert nor.op == "And"
        for side in nor.operands:
            assert isinstance(side, UnaryOp) and side.op == "BitwiseNeg" and side.operand.likes(x), side

    def test_a_loaded_piece_is_not_moved(self):
        # a load read at the definition may see another value at the read
        ptr = _reg(1, 64)
        v1 = _slot(2)
        loaded = Load(None, ptr, 4, LE, bits=32)
        graph = _graph(
            Assignment(10, v1, _ins(_ins(_c(0, 96), 4, _c(7, 32)), 8, loaded)),
            _branch(11, _ext(v1, 64, 4), _c(0, 64)),
        )
        forward_packed_slot_reads(graph)
        cond = _condition(graph)
        assert v1.varid in _vvar_ids(cond), f"the load was moved: {cond}"

    def test_a_call_result_is_not_duplicated(self):
        v1, v2 = _slot(2, 64), _slot(3)
        call = Call(None, _c(0x401000, 64), args=[], bits=64)
        graph = _graph(
            Assignment(10, v1, call),
            Assignment(11, v2, _ins(_ins(_c(0, 96), 4, _ext(v1, 32, 0)), 8, _ext(v1, 32, 0))),
            _branch(12, _nor_of_qword(_ext(v2, 64, 4)), _c(0, 32)),
        )
        forward_packed_slot_reads(graph)
        cond = _condition(graph)
        assert v2.varid not in _vvar_ids(cond)
        assert v1.varid in _vvar_ids(cond), f"the call was copied into the read: {cond}"

    def test_a_chain_of_self_nors_stays_linear(self):
        # each slot holds NOR(prev, prev) twice; unshared slices would double at every level
        x = _reg(1)
        stmts = [Assignment(10, _slot(100, 64), _ins(_ins(_c(0, 64), 0, x), 4, x))]
        prev = _slot(100, 64)
        for i in range(1, 14):
            nor = _nor_of_qword(prev)
            cur = _slot(100 + i, 64)
            stmts.append(Assignment(10 + i, cur, _ins(_ins(_c(0, 64), 0, nor), 4, nor)))
            prev = cur
        stmts.append(_branch(99, _nor_of_qword(prev), _c(0, 32)))
        graph = _graph(*stmts)
        # each read is forwarded once per distinct copy of it, not once per path through the chain (2**levels)
        assert forward_packed_slot_reads(graph) < 200
        cond = _condition(graph)
        # NOR(a, a) == ~a, so the condition is x complemented once per level
        assert cond.operands[0].depth < 20, cond.operands[0].depth

    def test_a_flag_bit_is_not_sliced_out_of_a_flags_word(self):
        # pushfd's flags word in a 4-byte slot; DF is read back as Conv(32->1, slot >> 10). The flags-word folds
        # match that read, so it must stay a read of the slot rather than become bit 10 of the slot's definition.
        a = _reg(1)
        flags = _slot(2, 32, -0x1b0)
        df = Convert(None, 32, 1, False, BinaryOp(None, "Shr", [flags, _c(10, 8)], False, bits=32))
        graph = _graph(
            Assignment(10, flags, BinaryOp(None, "Or", [a, _c(0x202, 32)], False, bits=32)),
            ConditionalJump(11, df, _c(1, 64), _c(2, 64)),
        )
        forward_packed_slot_reads(graph)
        assert flags.varid in _vvar_ids(_condition(graph)), _condition(graph)

    def test_a_select_of_whole_values_is_not_copied_into_reads(self):
        # Tigress keeps its state in a stack array updated by a select of two Inserts; slicing cannot take the
        # select apart, so every read would get a copy of it
        a, b, c = _reg(1, 64), _reg(2, 64), _reg(3, 1)
        prev = _slot(4, 128)
        state = _slot(5, 128)
        select = ITE(None, c, _ins(prev, 0, BinaryOp(None, "Add", [a, b], False, bits=64)), _ins(prev, 8, a))
        graph = _graph(
            Assignment(10, state, select),
            _branch(11, _ext(state, 64, 8), _ext(state, 64, 0)),
        )
        forward_packed_slot_reads(graph)
        cond = _condition(graph)
        assert state.varid in _vvar_ids(cond), cond


if __name__ == "__main__":
    unittest.main()

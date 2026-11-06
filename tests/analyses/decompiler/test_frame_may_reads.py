#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""VM-mode dead-store removal keeps stack stores that a load through an unresolved frame pointer may read."""
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

import angr
from angr import ailment
from angr.ailment.block import Block
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Load,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, Return, SideEffectStatement, Store
from angr.analyses.decompiler.frame_may_reads import frame_read_vvars


def _decompile(code: bytes) -> str:
    proj = angr.load_shellcode(code, "AMD64", load_address=0x400000, start_offset=0)
    cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000], fail_fast=True, show_progressbar=False)
    proj.analyses.CompleteCallingConventions(recover_variables=False)
    dec = proj.analyses.Decompiler(cfg.functions[0x400000], cfg=cfg, fail_fast=True, vm_deobfuscation=True)
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec.codegen.text


class TestFrameMayReads(unittest.TestCase):
    # sub rsp, 0x48; lea rax, [rsp]; mov [0x600000], rax; mov qword [rsp+0x20], 7; mov rax, [0x600000];
    # mov rax, [rax+DISP]; add rsp, 0x48; ret
    CODE = "4883ec48488d0424488904250000600048c744242007000000488b042500006000488b40{:02x}4883c448c3"

    def test_store_read_through_published_frame_pointer_is_kept(self):
        text = _decompile(bytes.fromhex(self.CODE.format(0x20)))
        assert re.search(r"\bv\d+ = 7;", text), text

    def test_store_out_of_the_pointer_reach_is_removed(self):
        text = _decompile(bytes.fromhex(self.CODE.format(0x30)))
        assert "= 7;" not in text, text

    def test_flag_bits_of_a_frame_address_do_not_point_into_the_frame(self):
        m = ailment.Manager()

        def const(value, bits=64):
            return Const(m.next_atom(), value, bits)

        slot = VirtualVariable(m.next_atom(), 10, 64, VirtualVariableCategory.STACK, oident=-0x28)
        base = VirtualVariable(m.next_atom(), 11, 64, VirtualVariableCategory.STACK, oident=-0x48)
        ref = UnaryOp(m.next_atom(), "Reference", base, bits=64)
        # (&base < 64) * 4, as a VM's flag computation would build it
        flag = BinaryOp(
            m.next_atom(),
            "Mul",
            [Convert(m.next_atom(), 1, 64, False, BinaryOp(m.next_atom(), "CmpLT", [ref, const(64)], bits=1)), const(4)],
            bits=64,
        )
        pointer = Load(m.next_atom(), const(0x5000), 8, "Iend_LE")
        load = Load(m.next_atom(), BinaryOp(m.next_atom(), "Add", [pointer, const(0x20)], bits=64), 8, "Iend_LE")
        block = Block(
            0x1000,
            0x10,
            statements=[
                Store(m.next_atom(), const(0x5000), flag, 8, "Iend_LE", ins_addr=0x1000),
                Assignment(m.next_atom(), slot, const(7), ins_addr=0x1004),
                Return(m.next_atom(), [load], ins_addr=0x1008),
            ],
            idx=0,
        )
        assert frame_read_vvars({(0x1000, 0): block}, {(0x1000, 0): []}) == set()
        # the address itself does
        block.statements[0] = Store(m.next_atom(), const(0x5000), ref, 8, "Iend_LE", ins_addr=0x1000)
        assert frame_read_vvars({(0x1000, 0): block}, {(0x1000, 0): []}) == {10}

    def test_key_loads_in_one_block_cancel(self):
        m = ailment.Manager()

        def const(value, bits=64):
            return Const(m.next_atom(), value, bits)

        def load(addr):
            return Load(m.next_atom(), const(addr), 8, "Iend_LE")

        def binop(op, a, b):
            return BinaryOp(m.next_atom(), op, [a, b], bits=64)

        slot = VirtualVariable(m.next_atom(), 10, 64, VirtualVariableCategory.STACK, oident=-0x18)
        base = VirtualVariable(m.next_atom(), 11, 64, VirtualVariableCategory.STACK, oident=-0x48)
        key = VirtualVariable(m.next_atom(), 12, 64, VirtualVariableCategory.REGISTER, oident=16)
        # [0x5000] = &base; key = [0x6000]; return *(([0x5000] + [0x6000] - 0x40) - key + 0x60)
        stmts = [
            Store(m.next_atom(), const(0x5000), UnaryOp(m.next_atom(), "Reference", base, bits=64), 8, "Iend_LE"),
            Assignment(m.next_atom(), slot, const(7)),
            Assignment(m.next_atom(), key, load(0x6000)),
        ]
        addr = binop("Add", binop("Sub", binop("Sub", binop("Add", load(0x5000), load(0x6000)), const(0x40)), key), const(0x60))
        ret = Return(m.next_atom(), [Load(m.next_atom(), addr, 8, "Iend_LE")])
        block = Block(0x1000, 0x10, statements=[*stmts, ret], idx=0)
        # the address is &base + 0x20 = s-0x28: the slot at s-0x18 is not read
        assert frame_read_vvars({(0x1000, 0): block}, {(0x1000, 0): []}) == set()
        # a store to the key between its loads may change it: the address is unknown, which reads the whole frame
        clobber = Store(m.next_atom(), const(0x6000), const(1), 8, "Iend_LE")
        block = Block(0x1000, 0x10, statements=[*stmts, clobber, ret], idx=0)
        assert frame_read_vvars({(0x1000, 0): block}, {(0x1000, 0): []}, unknown_reads=True) == {10}

    def test_callee_reads_the_object_up_to_the_next_address_taken_slot(self):
        m = ailment.Manager()

        def stack(varid, off):
            return VirtualVariable(m.next_atom(), varid, 64, VirtualVariableCategory.STACK, oident=off)

        def const(value):
            return Const(m.next_atom(), value, 64)

        # a at s-0x40 with a field at s-0x38 written on its own; b at s-0x30 has its address taken
        a, field, b = stack(10, -0x40), stack(11, -0x38), stack(12, -0x30)
        reg = VirtualVariable(m.next_atom(), 20, 64, VirtualVariableCategory.REGISTER, oident=16)
        call = Call(m.next_atom(), const(0x2000), args=[UnaryOp(m.next_atom(), "Reference", a, bits=64)])
        block = Block(
            0x1000,
            0x10,
            statements=[
                Assignment(m.next_atom(), a, const(1)),
                Assignment(m.next_atom(), field, const(2)),
                Assignment(m.next_atom(), b, const(3)),
                Assignment(m.next_atom(), reg, UnaryOp(m.next_atom(), "Reference", b, bits=64)),
                SideEffectStatement(m.next_atom(), call),
                Return(m.next_atom(), []),
            ],
            idx=0,
        )
        assert frame_read_vvars({(0x1000, 0): block}, {(0x1000, 0): []}) == {10, 11}
        # the same with b's address taken as a StackBaseOffset rather than a Reference
        block.statements[3] = Assignment(m.next_atom(), reg, StackBaseOffset(m.next_atom(), 64, -0x30))
        assert frame_read_vvars({(0x1000, 0): block}, {(0x1000, 0): []}) == {10, 11}

    @staticmethod
    def _indexed_read(index_of):
        """
        Slots at s-0x48 (the base, vvar 10), s-0x40 (11), ..., s-0x28 (14), each assigned; the function returns
        *(&base + index_of(x)) for x = [0x6000].
        """
        m = ailment.Manager()

        def const(value, bits=64):
            return Const(m.next_atom(), value, bits)

        def binop(op, a, b):
            return BinaryOp(m.next_atom(), op, [a, b], bits=64)

        slots = [
            VirtualVariable(m.next_atom(), 10 + i, 64, VirtualVariableCategory.STACK, oident=-0x48 + 8 * i)
            for i in range(5)
        ]
        x = VirtualVariable(m.next_atom(), 20, 64, VirtualVariableCategory.REGISTER, oident=16)
        idx = VirtualVariable(m.next_atom(), 21, 64, VirtualVariableCategory.REGISTER, oident=24)
        base = UnaryOp(m.next_atom(), "Reference", slots[0], bits=64)
        stmts = [Assignment(m.next_atom(), slot, const(i)) for i, slot in enumerate(slots)]
        stmts.append(Assignment(m.next_atom(), x, Load(m.next_atom(), const(0x6000), 8, "Iend_LE")))
        stmts.append(Assignment(m.next_atom(), idx, index_of(x, const, binop)))
        stmts.append(Return(m.next_atom(), [Load(m.next_atom(), binop("Add", base, idx), 8, "Iend_LE")]))
        block = Block(0x1000, 0x10, statements=stmts, idx=0)
        return frame_read_vvars({(0x1000, 0): block}, {(0x1000, 0): []})

    def test_index_of_known_bits_reads_its_slot(self):
        # ((x & 7) | 0x40) >> 3 is 8
        assert self._indexed_read(
            lambda x, const, binop: binop("Shr", binop("Or", binop("And", x, const(7)), const(0x40)), const(3, 8))
        ) == {11}
        # an index nothing bounds stays ignored
        assert self._indexed_read(lambda x, const, binop: x) == set()

    def test_index_range_reads_every_slot_it_covers(self):
        # (x & 3) * 8 is one of 0, 8, 16, 24
        assert self._indexed_read(lambda x, const, binop: binop("Mul", binop("And", x, const(3)), const(8))) == {
            10,
            11,
            12,
            13,
        }
        # x % 3 * 8 is 0, 8 or 16 (a range known bits miss)
        assert self._indexed_read(lambda x, const, binop: binop("Mul", binop("Mod", x, const(3)), const(8))) == {
            10,
            11,
            12,
        }


if __name__ == "__main__":
    unittest.main()

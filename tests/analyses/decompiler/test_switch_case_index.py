#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Load, Register
from angr.ailment.statement import ConditionalJump, Jump, Return
from angr.analyses.decompiler.decompilation_options import get_structurer_option
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import SwitchCaseNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.analyses.decompiler.utils import switch_jumptable_first_index
from angr.knowledge_plugins.cfg import IndirectJump, IndirectJumpType
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "x86_64")


def _unmapped(_addr: int) -> bool:
    return False


def _mapped(_addr: int) -> bool:
    return True


class TestSwitchJumptableFirstIndex(unittest.TestCase):
    """
    The table index of a jump table record's first entry, relative to the scaled base of the table load in the jump
    target.
    """

    def setUp(self):
        self.manager = Manager()
        self.index = Register(self.manager.next_atom(), 16, 32)

    def _const(self, value: int, bits: int = 64) -> Const:
        return Const(self.manager.next_atom(), value, bits)

    def _binop(self, op: str, a: Expression, b: Expression, bits: int = 64) -> BinaryOp:
        return BinaryOp(self.manager.next_atom(), op, [a, b], False, bits=bits)

    def _zext(self, expr: Expression, to_bits: int = 64) -> Convert:
        return Convert(self.manager.next_atom(), expr.bits, to_bits, False, expr)

    def _load(self, addr: Expression, size: int) -> Load:
        return Load(self.manager.next_atom(), addr, size, "Iend_LE")

    def test_absolute_table(self):
        # Load(K + idx * 8)
        target = self._load(
            self._binop("Add", self._binop("Mul", self._zext(self.index), self._const(8)), self._const(0x600000)), 8
        )
        r = switch_jumptable_first_index(target, 0x600010, 8, _unmapped)
        assert r is not None
        assert r[0] == 2
        assert r[1].likes(self._zext(self.index))

    def test_pic_table(self):
        # Conv(32->s64, Load(K + idx * 4) + K)
        load = self._load(
            self._binop("Add", self._const(0x42C1CC), self._binop("Mul", self._zext(self.index), self._const(4))), 4
        )
        offset = self._binop("Add", load, self._const(0x42C1CC, 32), bits=32)
        target = Convert(self.manager.next_atom(), 32, 64, True, offset)
        r = switch_jumptable_first_index(target, 0x42C1D0, 4, _unmapped)
        assert r is not None and r[0] == 1

    def test_shifted_index_and_mask(self):
        # Load(K + ((idx & 0xf) << 2))
        masked = self._binop("And", self._zext(self.index), self._const(0xF))
        target = self._load(self._binop("Add", self._const(0x5E3C90), self._binop("Shl", masked, self._const(2, 8))), 4)
        r = switch_jumptable_first_index(target, 0x5E3C94, 4, _unmapped)
        assert r is not None and r[0] == 1
        assert r[1].likes(masked)

    def test_byte_table(self):
        # Load(idx + K), one-byte entries
        target = self._load(self._binop("Add", self._zext(self.index), self._const(0x700000)), 1)
        r = switch_jumptable_first_index(target, 0x700003, 1, _unmapped)
        assert r is not None and r[0] == 3

    def test_entry_size_mismatch(self):
        target = self._load(
            self._binop("Add", self._binop("Mul", self._zext(self.index), self._const(8)), self._const(0x600000)), 8
        )
        assert switch_jumptable_first_index(target, 0x600010, 4, _unmapped) is None

    def test_table_below_base(self):
        target = self._load(
            self._binop("Add", self._binop("Mul", self._zext(self.index), self._const(8)), self._const(0x600000)), 8
        )
        assert switch_jumptable_first_index(target, 0x5FFFF8, 8, _unmapped) is None

    def test_second_level_table(self):
        # Load(K2 + Conv(Load(idx + K1)) * 4): entries of the outer table are not numbered by idx
        inner = self._load(self._binop("Add", self._zext(self.index), self._const(0x700000)), 1)
        outer = self._load(
            self._binop("Add", self._const(0x600000), self._binop("Mul", self._zext(inner), self._const(4))), 4
        )
        assert switch_jumptable_first_index(outer, 0x600004, 4, _mapped) is None
        # the index table itself is numbered by idx
        r = switch_jumptable_first_index(outer, 0x700001, 1, _mapped)
        assert r is not None and r[0] == 1

    def test_target_without_table_load(self):
        assert switch_jumptable_first_index(self._zext(self.index), 0x600000, 8, _unmapped) is None


class TestSwitchCaseIndexPhoenix(unittest.TestCase):
    """
    Phoenix numbers cases by the table index of each jump table entry, also when the record starts above index 0.
    """

    TABLE_BASE = 0x600000

    def _structure(self, head_cond: str | None, table_addr: int, index_expr_kind: str = "plain") -> dict:
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x400000)
        manager = Manager()

        def constant(value, bits=32):
            return Const(manager.next_atom(), value, bits)

        def ret_block(addr, value):
            return Block(addr, 4, statements=[Return(manager.next_atom(), [constant(value)], ins_addr=addr)])

        index = Register(manager.next_atom(), 8, 32)
        if index_expr_kind == "mask":
            table_index = BinaryOp(manager.next_atom(), "And", [index, constant(3)], False, bits=32)
        else:
            table_index = index
        offset = BinaryOp(manager.next_atom(), "Mul", [table_index, constant(4)], False, bits=32)
        address = BinaryOp(manager.next_atom(), "Add", [offset, constant(self.TABLE_BASE)], False, bits=32)
        dispatch = Block(
            0x400010,
            4,
            statements=[Jump(manager.next_atom(), Load(manager.next_atom(), address, 4, "Iend_LE"), ins_addr=0x400010)],
        )
        cases = [ret_block(0x400020 + 0x10 * i, i) for i in range(3)]
        default = ret_block(0x400070, 100)

        edges = [(dispatch, c) for c in cases]
        if head_cond is not None:
            if head_cond == "folded":
                # (idx - 2) <=u 3, with the table read at idx directly
                bound = BinaryOp(
                    manager.next_atom(),
                    "CmpLE",
                    [BinaryOp(manager.next_atom(), "Sub", [index, constant(2)], False, bits=32), constant(3)],
                    False,
                    bits=1,
                )
            else:
                bound = BinaryOp(manager.next_atom(), "CmpLE", [index, constant(3)], False, bits=1)
            head = Block(
                0x400000,
                4,
                statements=[
                    ConditionalJump(
                        manager.next_atom(), bound, constant(0x400010), constant(0x400070), ins_addr=0x400000
                    )
                ],
            )
            edges += [(head, dispatch), (head, default)]
        else:
            head = dispatch

        graph = networkx.DiGraph(edges)
        overlay = OverlayManager(graph)
        region = overlay.root.create_subregion(head, list(graph.nodes), cyclic=False)

        jump = IndirectJump(dispatch.addr, dispatch.addr, head.addr, "Ijk_Boring", 0)
        jump.type = IndirectJumpType.Jumptable_AddressLoadedFromMemory
        jump.jumptable = True
        jump.add_jumptable(table_addr, 12, 4, [c.addr for c in cases], is_primary=True)

        result = project.analyses[PhoenixStructurer].prep(fail_fast=True)(
            region, jump_tables={dispatch.addr: jump}, ail_manager=manager
        )
        assert result.result is not None

        switches: list[SwitchCaseNode] = []

        def handle_switch(node, **kwargs):
            switches.append(node)
            return walker._handle_SwitchCase(node, **kwargs)  # pylint:disable=protected-access

        walker = SequenceWalker(handlers={SwitchCaseNode: handle_switch})
        walker.walk(result.result)
        assert len(switches) == 1
        return {key: node.addr for key, node in switches[0].cases.items()}

    def test_record_starting_at_index_one(self):
        # if (idx <= 3) switch on Load(K + idx * 4); index 0 is unreachable, so the record starts at K + 4
        cases = self._structure("plain", self.TABLE_BASE + 4)
        assert cases == {1: 0x400020, 2: 0x400030, 3: 0x400040}

    def test_record_starting_at_index_zero(self):
        cases = self._structure("plain", self.TABLE_BASE)
        assert cases == {0: 0x400020, 1: 0x400030, 2: 0x400040}

    def test_offset_folded_into_table_base(self):
        # if ((idx - 2) <= 3) switch on Load(K + idx * 4): entry i of a record at K + 12 is case 3 + i, not 5 + i
        cases = self._structure("folded", self.TABLE_BASE + 12)
        assert cases == {3: 0x400020, 4: 0x400030, 5: 0x400040}

    def test_record_not_matching_the_table_load(self):
        # no load in the jump target reads the record; entry i is numbered cmp_lb + i
        cases = self._structure("plain", self.TABLE_BASE - 0x100)
        assert cases == {0: 0x400020, 1: 0x400030, 2: 0x400040}

    def test_masked_index_starting_at_index_one(self):
        # switch on Load(K + (idx & 3) * 4) without a bounds check; index 0 is excluded elsewhere
        cases = self._structure(None, self.TABLE_BASE + 4, index_expr_kind="mask")
        assert cases == {1: 0x400020, 2: 0x400030, 3: 0x400040}


class TestSwitchCaseIndexBinaries(unittest.TestCase):
    """
    Switches whose jump table record starts at the first reachable entry (the index is bounded from below).
    """

    @staticmethod
    def _decompile(bin_path: str, func_addr: int, window: int, jump_addr: int, base: int, first_index: int, **kwargs):
        proj, cfg = load_project_with_scoped_cfg(bin_path, func_addr, window=window, expand_call_tree=False)
        # resolvers without a deeper lower bound record the table from index 0; start it at the first reachable entry
        table = cfg.jump_tables[jump_addr].jumptables[0]
        assert table.addr is not None
        skipped = (table.addr - base) // table.entry_size
        assert 0 <= skipped <= first_index
        drop = first_index - skipped
        table.addr += drop * table.entry_size
        table.size -= drop * table.entry_size
        table.entries = table.entries[drop:]
        dec = proj.analyses.Decompiler(cfg.functions[func_addr], cfg=cfg, fail_fast=True, **kwargs)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec, dec.codegen.text

    def test_redis_acl_set_user_string_error(self):
        # switch (errno) after `errno <= 22` and `errno > 1`: the table has entries for indexes 2..22
        dec, text = self._decompile(
            os.path.join(test_location, "decompiler", "redis_server_O2"), 0xA05380, 0x200, 0xA0539A, 0xC171E8, 2
        )
        assert not dec.structuring_failures
        assert "switch (" in text
        assert re.search(r'case 2:\s*return "Unknown command or category name in ACL";', text)
        assert re.search(r'case 10:\s*return "Allowing first-arg of a subcommand', text)
        assert re.search(r'case 19:\s*return "The password you are trying to remove', text)
        assert re.search(r'case 22:\s*return "Syntax error";', text)
        assert "case 0:" not in text and "case 1:" not in text

    def test_libc_seterr_reply(self):
        # switch (ar_stat) after `ar_stat != 0`: the table has entries for indexes 1..5
        dec, text = self._decompile(
            os.path.join(test_location, "ioctl", "libc.so.6"), 0x55EBA0, 0x400, 0x55EC15, 0x5D6AC4, 1
        )
        assert not dec.structuring_failures
        assert "switch (" in text
        # PROG_UNAVAIL -> RPC_PROGUNAVAIL, ..., SYSTEM_ERR -> RPC_SYSTEMERROR
        for case_no, rpc_stat in ((1, 8), (3, 10), (4, 11), (5, 12)):
            assert re.search(rf"case {case_no}:\s*\*\(unsigned int \*\)a1 = {rpc_stat};", text), case_no

    def test_libselinux_avc_update_node(self):
        # `a0 != 0` above `a0 <= 32`: the table has entries for indexes 1..32
        dec, text = self._decompile(
            os.path.join(test_location, "decbench", "libselinux_O0_stripped.so"), 0x40B48A, 0x400, 0x40B4CC, 0x42C1CC, 1
        )
        assert not dec.structuring_failures
        assert "switch (" in text
        assert re.search(r"case 1:\s*a1\[5\] = a1\[5\] \| a2;", text)
        assert re.search(r"case 32:\s*a1\[7\] = a1\[7\] & ~a2;", text)

    def test_dream_libselinux_avc_update_node(self):
        _, text = self._decompile(
            os.path.join(test_location, "decbench", "libselinux_O0_stripped.so"),
            0x40B48A,
            0x400,
            0x40B4CC,
            0x42C1CC,
            1,
            options=[(get_structurer_option(), "dream")],
        )
        assert "switch (" in text
        assert re.search(r"case 1:\s*a1\[5\] = a1\[5\] \| a2;", text)
        assert re.search(r"case 32:\s*a1\[7\] = a1\[7\] & ~a2;", text)


if __name__ == "__main__":
    unittest.main()

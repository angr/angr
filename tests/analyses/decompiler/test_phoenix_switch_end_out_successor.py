#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.ailment import Block, Manager
from angr.ailment.expression import BinaryOp, Call, Const, Load, Register
from angr.ailment.statement import ConditionalJump, Jump, Return, SideEffectStatement
from angr.analyses.decompiler.region_overlay import OverlayManager
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import BreakNode, SwitchCaseNode
from angr.analyses.decompiler.structuring.phoenix import PhoenixStructurer
from angr.analyses.decompiler.utils import sequence_to_blocks
from angr.knowledge_plugins.cfg import IndirectJump, IndirectJumpType


class TestPhoenixSwitchEndOutSuccessor(unittest.TestCase):
    def test_switch_end_is_the_switch_out_successor_not_the_goto_majority(self):
        # switch (x) { case 0: f(); if (a) goto OUT; g(); if (b) goto OUT; ... case 1: h(); break; default: d();
        # break; } END: e(); goto OUT;
        # the region ends at END and OUT is the region successor (e.g., the head of an enclosing loop). the case-0
        # body has more gotos to OUT than there are gotos to END, so a majority vote over goto targets picked OUT as
        # the end of the switch: the gotos to OUT became breaks (which flow to END instead) and the gotos to END
        # stayed gotos.
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x400000)
        manager = Manager()

        def constant(value):
            return Const(manager.next_atom(), value, 32)

        def call(addr, target):
            return SideEffectStatement(
                manager.next_atom(), Call(manager.next_atom(), constant(target), args=[], bits=32), ins_addr=addr
            )

        def cond(reg):
            return BinaryOp(manager.next_atom(), "CmpEQ", [Register(manager.next_atom(), reg, 32), constant(0)], False)

        def cond_block(addr, target, reg, true_addr, false_addr):
            return Block(
                addr,
                4,
                statements=[
                    call(addr, target),
                    ConditionalJump(
                        manager.next_atom(), cond(reg), constant(true_addr), constant(false_addr), ins_addr=addr
                    ),
                ],
            )

        def goto_block(addr, target, dst_addr):
            return Block(
                addr, 4, statements=[call(addr, target), Jump(manager.next_atom(), constant(dst_addr), ins_addr=addr)]
            )

        index = Register(manager.next_atom(), 8, 32)
        out_addr = 0x400100
        end_addr = 0x400080
        check_cond = BinaryOp(manager.next_atom(), "CmpLE", [index, constant(1)], False, bits=1)
        head = Block(
            0x400000,
            4,
            statements=[
                ConditionalJump(
                    manager.next_atom(), check_cond, constant(0x400010), constant(0x400070), ins_addr=0x400000
                )
            ],
        )
        offset = BinaryOp(manager.next_atom(), "Mul", [index, constant(4)], False, bits=32)
        address = BinaryOp(manager.next_atom(), "Add", [offset, constant(0x600000)], False, bits=32)
        dispatch = Block(
            0x400010,
            4,
            statements=[Jump(manager.next_atom(), Load(manager.next_atom(), address, 4, "Iend_LE"), ins_addr=0x400010)],
        )
        # case 0: four conditional exits to OUT, then falls to END
        case0 = [
            cond_block(0x400020, 0x500000, 12, out_addr, 0x400030),
            cond_block(0x400030, 0x500010, 16, out_addr, 0x400040),
            cond_block(0x400040, 0x500020, 20, out_addr, 0x400050),
            cond_block(0x400050, 0x500030, 24, out_addr, end_addr),
        ]
        case1 = goto_block(0x400060, 0x500040, end_addr)
        default = goto_block(0x400070, 0x500050, end_addr)
        end = goto_block(end_addr, 0x500060, out_addr)
        out = Block(out_addr, 4, statements=[Return(manager.next_atom(), [constant(0)], ins_addr=out_addr)])

        graph = networkx.DiGraph(
            [
                (head, dispatch),
                (head, default),
                (dispatch, case0[0]),
                (dispatch, case1),
                (case0[0], case0[1]),
                (case0[1], case0[2]),
                (case0[2], case0[3]),
                (case0[3], end),
                (case1, end),
                (default, end),
                (end, out),
            ]
        )
        for b in case0:
            graph.add_edge(b, out)
        region_members = [n for n in graph.nodes if n is not out]
        overlay = OverlayManager(graph)
        region = overlay.root.create_subregion(head, region_members, cyclic=False)

        jump = IndirectJump(dispatch.addr, dispatch.addr, head.addr, "Ijk_Boring", 0)
        jump.type = IndirectJumpType.Jumptable_AddressLoadedFromMemory
        jump.jumptable = True
        jump.add_jumptable(0x600000, 8, 4, [case0[0].addr, case1.addr], is_primary=True)
        tables = {dispatch.addr: jump}

        result = project.analyses[PhoenixStructurer].prep(fail_fast=True)(
            region, jump_tables=tables, ail_manager=manager
        )
        assert result.result is not None

        switches: list[SwitchCaseNode] = []
        breaks: list[BreakNode] = []

        def handle_switch(node, **kwargs):
            switches.append(node)
            return walker._handle_SwitchCase(node, **kwargs)  # pylint:disable=protected-access

        def handle_break(node, **kwargs):  # pylint:disable=unused-argument
            breaks.append(node)

        walker = SequenceWalker(handlers={SwitchCaseNode: handle_switch, BreakNode: handle_break})
        walker.walk(result.result)
        assert len(switches) == 1

        blocks = sequence_to_blocks(result.result)
        missing = [hex(b.addr) for b in region_members if b is not dispatch and b not in blocks]
        assert not missing, missing

        # breaks leave the switch for END; a goto to OUT must never have become a break
        assert all(b.target == end_addr for b in breaks), [hex(b.target) for b in breaks]
        # the gotos to OUT (the region successor) stay gotos
        gotos_to_out = [
            s
            for block in blocks
            for s in block.statements
            if isinstance(s, Jump) and isinstance(s.target, Const) and s.target.value == out_addr
        ]
        assert len(gotos_to_out) == 5, len(gotos_to_out)

    def test_goto_into_the_default_body_is_not_the_switch_end(self):
        # switch (x) { case 0: f(); return; case 1: g(); return; default: d(); if (a) { d2(); } d3(); return; }
        # the switch has no successor. the only goto inside the construct is the one from the if-then body to d3(),
        # which is inside the default node; voting over goto targets made it the switch end and turned the goto into
        # a break that skips d3().
        project = angr.load_shellcode(b"\xc3", arch="x86", load_address=0x400000)
        manager = Manager()

        def constant(value):
            return Const(manager.next_atom(), value, 32)

        def call(addr, target):
            return SideEffectStatement(
                manager.next_atom(), Call(manager.next_atom(), constant(target), args=[], bits=32), ins_addr=addr
            )

        def ret_block(addr, target):
            return Block(addr, 4, statements=[call(addr, target), Return(manager.next_atom(), [], ins_addr=addr)])

        index = Register(manager.next_atom(), 8, 32)
        check_cond = BinaryOp(manager.next_atom(), "CmpLE", [index, constant(1)], False, bits=1)
        head = Block(
            0x400000,
            4,
            statements=[
                ConditionalJump(
                    manager.next_atom(), check_cond, constant(0x400010), constant(0x400040), ins_addr=0x400000
                )
            ],
        )
        offset = BinaryOp(manager.next_atom(), "Mul", [index, constant(4)], False, bits=32)
        address = BinaryOp(manager.next_atom(), "Add", [offset, constant(0x600000)], False, bits=32)
        dispatch = Block(
            0x400010,
            4,
            statements=[Jump(manager.next_atom(), Load(manager.next_atom(), address, 4, "Iend_LE"), ins_addr=0x400010)],
        )
        case0 = ret_block(0x400020, 0x500000)
        case1 = ret_block(0x400030, 0x500010)
        cond = BinaryOp(manager.next_atom(), "CmpEQ", [Register(manager.next_atom(), 12, 32), constant(0)], False)
        default = Block(
            0x400040,
            4,
            statements=[
                call(0x400040, 0x500020),
                ConditionalJump(manager.next_atom(), cond, constant(0x400050), constant(0x400060), ins_addr=0x400040),
            ],
        )
        default_then = Block(
            0x400050,
            4,
            statements=[call(0x400050, 0x500030), Jump(manager.next_atom(), constant(0x400060), ins_addr=0x400050)],
        )
        default_tail = ret_block(0x400060, 0x500040)

        graph = networkx.DiGraph(
            [
                (head, dispatch),
                (head, default),
                (dispatch, case0),
                (dispatch, case1),
                (default, default_then),
                (default, default_tail),
                (default_then, default_tail),
            ]
        )
        overlay = OverlayManager(graph)
        overlay.root.head = head

        jump = IndirectJump(dispatch.addr, dispatch.addr, head.addr, "Ijk_Boring", 0)
        jump.type = IndirectJumpType.Jumptable_AddressLoadedFromMemory
        jump.jumptable = True
        jump.add_jumptable(0x600000, 8, 4, [case0.addr, case1.addr], is_primary=True)

        result = project.analyses[PhoenixStructurer].prep(fail_fast=True)(
            overlay.root, jump_tables={dispatch.addr: jump}, ail_manager=manager
        )
        assert result.result is not None

        switches: list[SwitchCaseNode] = []
        breaks: list[BreakNode] = []

        def handle_switch(node, **kwargs):
            switches.append(node)
            return walker._handle_SwitchCase(node, **kwargs)  # pylint:disable=protected-access

        def handle_break(node, **kwargs):  # pylint:disable=unused-argument
            breaks.append(node)

        walker = SequenceWalker(handlers={SwitchCaseNode: handle_switch, BreakNode: handle_break})
        walker.walk(result.result)
        assert len(switches) == 1
        assert switches[0].default_node is not None
        assert not breaks, [hex(b.target) for b in breaks]
        blocks = sequence_to_blocks(result.result)
        assert default_tail in blocks


if __name__ == "__main__":
    unittest.main()

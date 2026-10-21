#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import archinfo
import networkx

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Return
from angr.analyses.decompiler.ail_simplifier import AILSimplifier
from angr.analyses.s_reaching_definitions.s_rda_model import SRDAModel, populate_model

ENTRY, LOOP, EXIT = 0x400000, 0x400010, 0x400020


def _reg(varid: int) -> VirtualVariable:
    return VirtualVariable(varid, varid, 32, VirtualVariableCategory.REGISTER, oident=16)


def _update(dst: int, src: int, flag: int, addr: int) -> Assignment:
    # dst = src & 0x0fffffff | flag, the shape of a FPSCR update that only feeds the next one
    masked = BinaryOp(None, "And", [_reg(src), Const(None, 0x0FFFFFFF, 32)], False, bits=32)
    return Assignment(
        None, _reg(dst), BinaryOp(None, "Or", [masked, Const(None, flag, 32)], False, bits=32), ins_addr=addr
    )


def _cyclic_dead_vvars(blocks: dict[tuple[int, int], Block], edges: list[tuple[int, int]]) -> set[int]:
    graph = networkx.DiGraph()
    for src, dst in edges:
        graph.add_edge(blocks[(src, 0)], blocks[(dst, 0)])
    model = SRDAModel(None, None, archinfo.ArchARMCortexM())
    populate_model(model, blocks, None)

    simplifier = AILSimplifier.__new__(AILSimplifier)
    simplifier.func_graph = graph
    simplifier._dirty_vvar_scan_cache = {}
    return simplifier._find_cyclic_dependent_phis_and_dirty_vvars(model, set())


class TestCyclicDeadAssignments(unittest.TestCase):
    def test_loop_carried_chain_through_a_non_phi_assignment_is_dead(self):
        # v1 = phi(v0, v3); v2 = v1 & 0x0fffffff | 1; v3 = v2 & 0x0fffffff | 2 -- v2 is neither a phi nor a phi
        # operand, and nothing outside the cycle reads v1, v2 or v3
        counter = BinaryOp(None, "CmpLT", [_reg(10), Const(None, 3, 32)], False, bits=1)
        blocks = {
            (ENTRY, 0): Block(
                ENTRY,
                4,
                statements=[
                    Assignment(None, _reg(0), Const(None, 0, 32), ins_addr=ENTRY),
                ],
            ),
            (LOOP, 0): Block(
                LOOP,
                12,
                statements=[
                    Assignment(
                        None, _reg(1), Phi(None, 32, [((ENTRY, 0), _reg(0)), ((LOOP, 0), _reg(3))]), ins_addr=LOOP
                    ),
                    _update(2, 1, 1, LOOP + 4),
                    _update(3, 2, 2, LOOP + 8),
                    ConditionalJump(None, counter, Const(None, LOOP, 32), Const(None, EXIT, 32), ins_addr=LOOP + 8),
                ],
            ),
            (EXIT, 0): Block(EXIT, 4, statements=[Return(None, [], ins_addr=EXIT)]),
        }
        dead = _cyclic_dead_vvars(blocks, [(ENTRY, LOOP), (LOOP, LOOP), (LOOP, EXIT)])
        assert {1, 2, 3} <= dead, dead

    def test_chain_read_outside_the_cycle_is_kept(self):
        counter = BinaryOp(None, "CmpLT", [_reg(10), Const(None, 3, 32)], False, bits=1)
        blocks = {
            (ENTRY, 0): Block(
                ENTRY,
                4,
                statements=[
                    Assignment(None, _reg(0), Const(None, 0, 32), ins_addr=ENTRY),
                ],
            ),
            (LOOP, 0): Block(
                LOOP,
                12,
                statements=[
                    Assignment(
                        None, _reg(1), Phi(None, 32, [((ENTRY, 0), _reg(0)), ((LOOP, 0), _reg(3))]), ins_addr=LOOP
                    ),
                    _update(2, 1, 1, LOOP + 4),
                    _update(3, 2, 2, LOOP + 8),
                    ConditionalJump(None, counter, Const(None, LOOP, 32), Const(None, EXIT, 32), ins_addr=LOOP + 8),
                ],
            ),
            # the value of the chain is returned
            (EXIT, 0): Block(EXIT, 4, statements=[Return(None, [_reg(2)], ins_addr=EXIT)]),
        }
        dead = _cyclic_dead_vvars(blocks, [(ENTRY, LOOP), (LOOP, LOOP), (LOOP, EXIT)])
        assert not ({1, 2, 3} & dead), dead


if __name__ == "__main__":
    unittest.main()

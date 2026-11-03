#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Jump
from angr.analyses.decompiler.equal_value_reuse import EqualValueReuser


def _tmp(varid):
    return VirtualVariable(varid, varid, 32, VirtualVariableCategory.TMP, oident=varid)


def _reg(varid, reg_offset=8):
    return VirtualVariable(varid, varid, 32, VirtualVariableCategory.REGISTER, oident=reg_offset)


def _op(op, a, b, idx):
    return BinaryOp(idx, op, [a, b], False, bits=32)


def _c(value, idx):
    return Const(idx, value, 32)


def _key(base, idx):
    # (base ^ 0x5d) - 0x41 spelled out anew each time
    return _op("Sub", _op("Xor", base, _c(0x5D, idx + 1), idx + 2), _c(0x41, idx + 3), idx + 4)


def _jump(target):
    return Jump(900, Const(901, target, 32), ins_addr=target)


def _run(graph, entry):
    reuser = EqualValueReuser(graph, entry)
    return reuser, reuser.run()


class TestEqualValueReuse(unittest.TestCase):
    def test_recomputation_in_the_same_block_reads_the_holder(self):
        # v2 = K; v3 = K + 7  ==>  v3 = v2 + 7
        block = Block(
            0x10,
            1,
            statements=[
                Assignment(1, _tmp(2), _key(_tmp(1), 10), ins_addr=0x10),
                Assignment(2, _tmp(3), _op("Add", _key(_tmp(1), 20), _c(7, 30), 31), ins_addr=0x11),
            ],
        )
        graph = networkx.DiGraph()
        graph.add_node(block)
        reuser, repl = _run(graph, block)
        assert reuser.reused == 1
        assert repl[block].statements[1].src.likes(_op("Add", _tmp(2), _c(7, 40), 41))
        # the holder keeps its own definition
        assert repl[block].statements[0].src.likes(_key(_tmp(1), 50))

    def test_holder_must_dominate(self):
        def diamond(head_defs_key):
            # head -> (a | b) -> join; a and b each compute K, so does the join
            head_stmts = [Assignment(7, _tmp(5), _key(_tmp(1), 40), ins_addr=0x10)] if head_defs_key else []
            head_stmts.append(ConditionalJump(1, _tmp(1), _c(0x20, 2), _c(0x30, 3), ins_addr=0x10))
            head = Block(0x10, 1, statements=head_stmts)
            a = Block(0x20, 1, statements=[Assignment(4, _tmp(2), _key(_tmp(1), 10), ins_addr=0x20), _jump(0x40)])
            b = Block(0x30, 1, statements=[Assignment(5, _tmp(3), _key(_tmp(1), 20), ins_addr=0x30), _jump(0x40)])
            join = Block(0x40, 1, statements=[Assignment(6, _tmp(4), _key(_tmp(1), 30), ins_addr=0x40)])
            graph = networkx.DiGraph()
            graph.add_edges_from([(head, a), (head, b), (a, join), (b, join)])
            return graph, head, a, b, join

        # neither arm dominates the other or the join
        graph, head, *_ = diamond(False)
        reuser, repl = _run(graph, head)
        assert reuser.reused == 0 and not repl

        # a definition in the head dominates both arms and the join
        graph, head, a, b, join = diamond(True)
        reuser, repl = _run(graph, head)
        assert reuser.reused == 3
        for blk in (a, b, join):
            assert repl[blk].statements[0].src.likes(_tmp(5))

    def test_register_vvars_and_memory_reads_are_not_reused(self):
        # a register vvar may share its C variable with a later definition of the register; a load may read
        # something else the second time
        load = Load(11, _c(0x4260B78, 12), 4, "Iend_LE")
        block = Block(
            0x10,
            1,
            statements=[
                Assignment(1, _reg(2), _key(_tmp(1), 10), ins_addr=0x10),
                Assignment(2, _tmp(3), _op("Add", load, _c(1, 13), 14), ins_addr=0x11),
                Assignment(3, _tmp(4), _key(_tmp(1), 20), ins_addr=0x12),
                Assignment(
                    4, _tmp(5), _op("Add", Load(15, _c(0x4260B78, 16), 4, "Iend_LE"), _c(1, 17), 18), ins_addr=0x13
                ),
            ],
        )
        graph = networkx.DiGraph()
        graph.add_node(block)
        reuser, repl = _run(graph, block)
        assert reuser.reused == 0 and not repl


if __name__ == "__main__":
    unittest.main()

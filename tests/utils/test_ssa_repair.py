#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.utils"  # pylint:disable=redefined-builtin

import unittest

import networkx

from angr.ailment import Block
from angr.ailment.expression import Const, Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Jump
from angr.utils.ssa import is_phi_assignment
from angr.utils.ssa.repair import repair_multiple_definitions


def _vvar(manager, varid, bits=32):
    return VirtualVariable(manager.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=16)


def _assign(manager, dst, value):
    return Assignment(manager.next_atom(), dst, Const(manager.next_atom(), value, dst.bits))


def _jump(manager, target):
    return Jump(manager.next_atom(), Const(manager.next_atom(), target, 64))


def _definitions(graph):
    defs = {}
    for block in graph:
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                defs.setdefault(stmt.dst.varid, []).append(block)
    return defs


class TestRepairMultipleDefinitions(unittest.TestCase):
    """A diamond whose two arms both define the same vvar -- what block duplication leaves behind."""

    def _diamond(self):
        manager = Manager(arch=None)
        head = Block(0x1000, 1, statements=[_jump(manager, 0x2000)])
        left = Block(0x2000, 1, statements=[_assign(manager, _vvar(manager, 100), 1), _jump(manager, 0x4000)])
        right = Block(0x3000, 1, statements=[_assign(manager, _vvar(manager, 100), 2), _jump(manager, 0x4000)])
        join = Block(
            0x4000,
            1,
            statements=[Assignment(manager.next_atom(), _vvar(manager, 200), _vvar(manager, 100))],
        )
        graph = networkx.DiGraph()
        graph.add_edge(head, left)
        graph.add_edge(head, right)
        graph.add_edge(left, join)
        graph.add_edge(right, join)
        return manager, graph, head, left, right, join

    def test_duplicate_definition_is_renamed(self):
        manager, graph, head, left, right, _join = self._diamond()
        assert len(_definitions(graph)[100]) == 2, "the fixture must start out broken"

        repair_multiple_definitions(graph, head, manager, 0x9000)

        for varid, blocks in _definitions(graph).items():
            assert len(blocks) == 1, f"vvar {varid} is still defined in {len(blocks)} blocks"
        assert left.statements[0].dst.varid != right.statements[0].dst.varid

    def test_phi_is_placed_at_the_join(self):
        manager, graph, head, left, right, join = self._diamond()
        repair_multiple_definitions(graph, head, manager, 0x9000)

        phis = [s for s in join.statements if is_phi_assignment(s)]
        assert len(phis) == 1, f"expected one phi at the join, found {len(phis)}"
        operands = {src: (vvar.varid if vvar is not None else None) for src, vvar in phis[0].src.src_and_vvars}
        assert operands == {
            (left.addr, left.idx): left.statements[0].dst.varid,
            (right.addr, right.idx): right.statements[0].dst.varid,
        }, f"phi operands do not name each arm's own version: {operands}"

    def test_use_reads_the_phi(self):
        manager, graph, head, _left, _right, join = self._diamond()
        repair_multiple_definitions(graph, head, manager, 0x9000)

        phi_dst = next(s.dst.varid for s in join.statements if is_phi_assignment(s))
        use = next(s for s in join.statements if not is_phi_assignment(s))
        assert use.src.varid == phi_dst, "the use must read the merged value, not one arm's version"

    def test_fresh_ids_start_where_told_and_are_returned(self):
        manager, graph, head, *_ = self._diamond()
        next_id = repair_multiple_definitions(graph, head, manager, 0x9000)
        minted = {
            s.dst.varid
            for b in graph
            for s in b.statements
            if isinstance(s, Assignment) and isinstance(s.dst, VirtualVariable) and s.dst.varid >= 0x9000
        }
        assert minted, "no fresh variables were allocated"
        assert next_id > max(minted), "the returned id must be past everything allocated"

    def test_clean_graph_is_untouched(self):
        manager, graph, head, _left, right, _join = self._diamond()
        # make the two arms define different variables: nothing to repair
        right.statements[0] = _assign(manager, _vvar(manager, 101), 2)
        before = {id(b): list(b.statements) for b in graph}

        next_id = repair_multiple_definitions(graph, head, manager, 0x9000)

        assert next_id == 0x9000, "an already-valid graph must not allocate anything"
        for block in graph:
            assert block.statements == before[id(block)]

    def test_use_dominated_by_one_arm_reads_that_arm(self):
        """The case that exposed the dominator-tree walk: a use inside one arm's subtree."""
        manager, graph, head, _left, right, join = self._diamond()
        tail = Block(0x3500, 1, statements=[Assignment(manager.next_atom(), _vvar(manager, 300), _vvar(manager, 100))])
        graph.remove_edge(right, join)
        graph.add_edge(right, tail)
        graph.add_edge(tail, join)

        repair_multiple_definitions(graph, head, manager, 0x9000)

        assert tail.statements[0].src.varid == right.statements[0].dst.varid, (
            "a use dominated solely by the right arm must read the right arm's version"
        )


class TestRepairDuplicatedPhiDefinitions(unittest.TestCase):
    """Duplicating a block that starts with phis duplicates the phi destinations too."""

    def _diamond_with_phis(self):
        manager = Manager(arch=None)
        head = Block(0x1000, 1, statements=[_jump(manager, 0x2000)])
        # both arms are copies of one block, so both define vvar 100 with a phi
        left = Block(
            0x2000,
            1,
            statements=[
                Assignment(
                    manager.next_atom(),
                    _vvar(manager, 100),
                    Phi(manager.next_atom(), 32, [((0x1000, None), _vvar(manager, 10))]),
                ),
                _jump(manager, 0x4000),
            ],
        )
        right = Block(
            0x2000,
            1,
            statements=[
                Assignment(
                    manager.next_atom(),
                    _vvar(manager, 100),
                    Phi(manager.next_atom(), 32, [((0x1000, None), _vvar(manager, 11))]),
                ),
                _jump(manager, 0x4000),
            ],
            idx=1,
        )
        join = Block(
            0x4000,
            1,
            statements=[Assignment(manager.next_atom(), _vvar(manager, 200), _vvar(manager, 100))],
        )
        graph = networkx.DiGraph()
        graph.add_edge(head, left)
        graph.add_edge(head, right)
        graph.add_edge(left, join)
        graph.add_edge(right, join)
        return manager, graph, head, left, right, join

    def test_phi_destinations_are_versioned(self):
        manager, graph, head, left, right, _join = self._diamond_with_phis()
        assert len(_definitions(graph)[100]) == 2, "the fixture must start out broken"

        repair_multiple_definitions(graph, head, manager, 0x9000)

        for varid, blocks in _definitions(graph).items():
            assert len(blocks) == 1, f"vvar {varid} is still defined in {len(blocks)} blocks"
        assert left.statements[0].dst.varid != right.statements[0].dst.varid
        assert is_phi_assignment(left.statements[0]) and is_phi_assignment(right.statements[0]), (
            "versioning a phi definition must not turn it into something else"
        )

    def test_phi_operands_are_left_alone(self):
        """Operands belong to specific predecessors; only the destination is versioned."""
        manager, graph, head, left, right, _join = self._diamond_with_phis()
        before = [list(b.statements[0].src.src_and_vvars) for b in (left, right)]

        repair_multiple_definitions(graph, head, manager, 0x9000)

        after = [list(b.statements[0].src.src_and_vvars) for b in (left, right)]
        assert before == after

    def test_use_after_a_duplicated_phi_reads_the_merge(self):
        manager, graph, head, _left, _right, join = self._diamond_with_phis()
        repair_multiple_definitions(graph, head, manager, 0x9000)

        merge = [s for s in join.statements if is_phi_assignment(s)]
        assert len(merge) == 1, f"expected one merge phi at the join, found {len(merge)}"
        use = next(s for s in join.statements if not is_phi_assignment(s))
        assert use.src.varid == merge[0].dst.varid


if __name__ == "__main__":
    unittest.main()

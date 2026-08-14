#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

import networkx

from angr.ailment import Block
from angr.ailment.expression import Const, Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Jump
from angr.utils.ssa.validate import (
    ALL_CHECKS,
    BAD_ENTRY,
    DUPLICATE_BLOCK,
    PHI_MISSING_PREDECESSOR,
    PHI_SOURCE_NOT_PREDECESSOR,
    PHI_SOURCE_REMOVED,
    VVAR_REDEFINED,
    check_ail_graph,
)
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")

# A phi that does not mention one of its predecessors is a real defect, but no pass
# repairs it yet and the right value to supply is an open question, so it would mask
# everything else here. Everything the repairs do cover is checked.
REPAIRED_CHECKS = ALL_CHECKS - {PHI_MISSING_PREDECESSOR}

# Functions whose decompiled graph was malformed before the phi-source and
# duplicate-definition repairs landed. Found by validating every function of these
# binaries with the repairs disabled; kept as the regression corpus because the
# breakage only shows up on real switch lowering, dead-block removal and return
# duplication, which is awkward to fake.
KNOWN_BAD = [
    ("mv_0", "rpl_fchmodat", 0x40BB60),
    ("mv_0", "fts_build", 0x40D200),
    ("mv_0", "prompt", 0x403E80),
    ("mv_0", "areadlinkat_with_size", 0x40AC20),
    ("grep_gcc17.0.0_O2", "rpl_fopen", 0x48ABC0),
    ("grep_gcc17.0.0_O2", "grepbuf", 0x4115A0),
    ("grep_gcc17.0.0_O2", "excluded_file_name", 0x4482B0),
    ("grep_gcc17.0.0_O2", "mbscasecmp", 0x463180),
    ("grep_gcc17.0.0_O2", "xstrtoimax", 0x4888A0),
]


def _vvar(manager, varid, bits=32):
    return VirtualVariable(manager.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=16)


class TestCheckAILGraph(unittest.TestCase):
    """The checker itself, on graphs built to break exactly one rule each."""

    @staticmethod
    def _two_arm_graph(manager):
        head = Block(0x1000, 1, statements=[Jump(manager.next_atom(), Const(manager.next_atom(), 0x2000, 64))])
        left = Block(0x2000, 1, statements=[Jump(manager.next_atom(), Const(manager.next_atom(), 0x4000, 64))])
        right = Block(0x3000, 1, statements=[Jump(manager.next_atom(), Const(manager.next_atom(), 0x4000, 64))])
        join = Block(0x4000, 1, statements=[])
        graph = networkx.DiGraph()
        graph.add_edge(head, left)
        graph.add_edge(head, right)
        graph.add_edge(left, join)
        graph.add_edge(right, join)
        return graph, head, left, right, join

    def test_clean_graph_reports_nothing(self):
        manager = Manager(arch=None)
        graph, head, left, right, join = self._two_arm_graph(manager)
        join.statements = [
            Assignment(
                manager.next_atom(),
                _vvar(manager, 100),
                Phi(
                    manager.next_atom(),
                    32,
                    [((left.addr, left.idx), _vvar(manager, 10)), ((right.addr, right.idx), _vvar(manager, 11))],
                ),
            )
        ]
        assert check_ail_graph(graph, head.addr) == []

    def test_detects_a_redefined_vvar(self):
        manager = Manager(arch=None)
        graph, head, left, right, _join = self._two_arm_graph(manager)
        for block in (left, right):
            block.statements.insert(
                0, Assignment(manager.next_atom(), _vvar(manager, 100), Const(manager.next_atom(), 1, 32))
            )

        kinds = {p.kind for p in check_ail_graph(graph, head.addr)}
        assert VVAR_REDEFINED in kinds

    def test_detects_a_phi_naming_a_removed_block(self):
        manager = Manager(arch=None)
        graph, head, _left, _right, join = self._two_arm_graph(manager)
        join.statements = [
            Assignment(
                manager.next_atom(),
                _vvar(manager, 100),
                Phi(manager.next_atom(), 32, [((0xDEAD, None), _vvar(manager, 10))]),
            )
        ]
        problems = check_ail_graph(graph, head.addr, checks={PHI_SOURCE_REMOVED})
        assert [p.kind for p in problems] == [PHI_SOURCE_REMOVED]
        assert "0xdead" in str(problems[0])

    def test_detects_a_phi_naming_a_non_predecessor(self):
        manager = Manager(arch=None)
        graph, head, _left, _right, join = self._two_arm_graph(manager)
        join.statements = [
            Assignment(
                manager.next_atom(),
                _vvar(manager, 100),
                # head is in the graph but does not flow straight into the join
                Phi(manager.next_atom(), 32, [((head.addr, head.idx), _vvar(manager, 10))]),
            )
        ]
        problems = check_ail_graph(graph, head.addr, checks={PHI_SOURCE_NOT_PREDECESSOR})
        assert [p.kind for p in problems] == [PHI_SOURCE_NOT_PREDECESSOR]

    def test_detects_a_predecessor_with_no_operand(self):
        manager = Manager(arch=None)
        graph, head, left, _right, join = self._two_arm_graph(manager)
        join.statements = [
            Assignment(
                manager.next_atom(),
                _vvar(manager, 100),
                Phi(manager.next_atom(), 32, [((left.addr, left.idx), _vvar(manager, 10))]),
            )
        ]
        problems = check_ail_graph(graph, head.addr, checks={PHI_MISSING_PREDECESSOR})
        assert [p.kind for p in problems] == [PHI_MISSING_PREDECESSOR]

    def test_detects_duplicate_block_locations(self):
        manager = Manager(arch=None)
        graph, head, _left, _right, _join = self._two_arm_graph(manager)
        graph.add_edge(head, Block(0x2000, 1, statements=[]))

        assert DUPLICATE_BLOCK in {p.kind for p in check_ail_graph(graph, head.addr)}

    def test_detects_a_missing_entry_block(self):
        manager = Manager(arch=None)
        graph, head, _left, _right, _join = self._two_arm_graph(manager)

        assert BAD_ENTRY in {p.kind for p in check_ail_graph(graph, 0x9999)}
        assert BAD_ENTRY not in {p.kind for p in check_ail_graph(graph, head.addr)}

    def test_checks_can_be_narrowed(self):
        manager = Manager(arch=None)
        graph, head, _left, _right, join = self._two_arm_graph(manager)
        join.statements = [
            Assignment(
                manager.next_atom(),
                _vvar(manager, 100),
                Phi(manager.next_atom(), 32, [((0xDEAD, None), _vvar(manager, 10))]),
            )
        ]
        assert check_ail_graph(graph, head.addr, checks={VVAR_REDEFINED}) == []


class TestDecompiledGraphsAreValid(unittest.TestCase):
    """Real functions that used to come out of the decompiler malformed."""

    @classmethod
    def setUpClass(cls):
        # one scoped CFG per binary covering all of its targets: building nine separate
        # ones costs about ten times as much as building two
        cls.projects = {}
        by_binary: dict[str, list[int]] = {}
        for binary, _name, addr in KNOWN_BAD:
            by_binary.setdefault(binary, []).append(addr)
        for binary, addrs in by_binary.items():
            cls.projects[binary] = load_project_with_scoped_cfg(
                os.path.join(test_location, "x86_64", binary), addrs[0], extra_func_addrs=addrs[1:]
            )

    def test_known_bad_functions_are_now_valid(self):
        for binary, name, addr in KNOWN_BAD:
            with self.subTest(binary=binary, function=name):
                proj, cfg = self.projects[binary]
                func = cfg.functions[addr]
                dec = proj.analyses.Decompiler(func, cfg=cfg.model)
                assert dec.ail_graph is not None, f"{binary}:{addr:#x} produced no AIL graph"
                problems = check_ail_graph(dec.ail_graph, func.addr, checks=REPAIRED_CHECKS)
                assert not problems, f"{binary} {name}: " + "; ".join(str(p) for p in problems[:5])

    def test_a_whole_binary_decompiles_to_valid_graphs(self):
        """A net over every function of a small binary, to catch a future pass that
        starts producing malformed graphs somewhere the corpus above does not reach.
        1after909 is clean today even with the repairs switched off."""
        import angr  # pylint:disable=import-outside-toplevel

        proj = angr.Project(os.path.join(test_location, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()

        checked = 0
        for func in cfg.functions.values():
            if func.is_simprocedure or func.is_plt or func.is_alignment:
                continue
            try:
                dec = proj.analyses.Decompiler(func, cfg=cfg.model)
            except Exception:  # pylint:disable=broad-except
                continue
            if dec.ail_graph is None:
                continue
            checked += 1
            problems = check_ail_graph(dec.ail_graph, func.addr, checks=REPAIRED_CHECKS)
            assert not problems, f"{func.name}: " + "; ".join(str(p) for p in problems[:5])
        assert checked > 5, f"only {checked} functions decompiled; the net is not catching anything"


if __name__ == "__main__":
    unittest.main()

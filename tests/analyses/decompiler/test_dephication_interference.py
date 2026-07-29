#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest
from collections import defaultdict

from angr.ailment.expression import Phi, VirtualVariable
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.s_liveness import SLivenessAnalysis
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")


class TestDephicationInterference(unittest.TestCase):
    """
    SSA destruction merges every virtual variable in a phi congruence class into a single variable, and performs no
    interference test of its own -- it is correct only when handed conventional SSA. Establishing that is
    GraphDephicationVVarMapping's job.

    A congruence class is the transitive closure over phi statements, so two vvars that never appear together in one
    phi statement can still end up in the same class through a chain of them. Testing interference only among the
    operands of a single phi therefore misses those pairs, and merging two simultaneously live values into one
    variable silently changes what the decompiled code means.

    gettok() (9base awk, lex.c:108, gcc 4.9.2 -O2) is a small function where two vvars reach one congruence class
    through separate phi statements while being live at the same time.
    """

    GETTOK_ADDR = 0x403010

    @staticmethod
    def _naive_congruence_classes(graph) -> dict[int, list[int]]:
        """The transitive phi closure that SSA destruction performs, as a union-find."""
        parent: dict[int, int] = {}

        def find(x: int) -> int:
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for block in graph:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi):
                    for _, vvar in stmt.src.src_and_vvars:
                        if vvar is None:
                            continue
                        root_dst, root_src = find(stmt.dst.varid), find(vvar.varid)
                        if root_dst != root_src:
                            parent[max(root_dst, root_src)] = min(root_dst, root_src)

        classes = defaultdict(list)
        for varid in parent:
            classes[find(varid)].append(varid)
        return classes

    def test_congruence_classes_are_conventional(self):
        bin_path = os.path.join(test_location, "x86_64", "ALLSTAR_9base_awk")
        proj, cfg = load_project_with_scoped_cfg(bin_path, self.GETTOK_ADDR, run_ccc=False)
        func = cfg.functions[self.GETTOK_ADDR]

        interfering: list[tuple[int, int]] = []
        original = Clinic._collect_dephi_vvar_mapping_and_rewrite_blocks

        def collect(clinic, ail_graph, arg_vvars):
            mapping, copied = original(clinic, ail_graph, arg_vvars)
            liveness = clinic.project.analyses[SLivenessAnalysis].prep()(
                clinic.function,
                func_graph=ail_graph,
                entry=next(bb for bb in ail_graph if (bb.addr, bb.idx) == clinic.entry_node_addr),
                arg_vvars=[vvar for vvar, _ in arg_vvars.values()],
            )
            interference = liveness.interference_graph()
            for members in self._naive_congruence_classes(ail_graph).values():
                for i, first in enumerate(members):
                    for second in members[i + 1 :]:
                        # first != second: a self-loop says nothing about whether two *different* vvars may share
                        # a variable, and SLivenessAnalysis puts one on nearly every node
                        if first != second and interference.has_edge(first, second):
                            interfering.append((first, second))
            return mapping, copied

        Clinic._collect_dephi_vvar_mapping_and_rewrite_blocks = collect
        try:
            dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        finally:
            Clinic._collect_dephi_vvar_mapping_and_rewrite_blocks = original

        assert dec.codegen is not None
        assert not interfering, (
            "simultaneously live vvars share a phi congruence class, so SSA destruction will merge them into one "
            f"variable: {interfering}"
        )


if __name__ == "__main__":
    unittest.main()

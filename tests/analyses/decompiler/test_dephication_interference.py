#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest
from collections import defaultdict

from angr.ailment.expression import Phi, VirtualVariable
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.s_liveness import SLivenessAnalysis
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDephicationInterference(unittest.TestCase):
    """
    The original implementation of Dephication did not properly check for all phi variables in a congruence class.
    Instead, it only went the operands of each phi statement and checked for interference among them.

    As such, two vvars that never appear together in one phi statement can still end up in the same phi congruence
    class through a chain, but my original implementation missed these.
    """

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
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x403010, run_ccc=False)  # gettok
        func = cfg.functions[0x403010]

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

        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        assert not interfering, (
            "simultaneously live vvars share a phi congruence class, so SSA destruction will merge them into one "
            f"variable: {interfering}"
        )

    def test_congruence_classes_causing_incorrect_branch_conditions(self):
        bin_path = os.path.join(test_location, "x86_64", "cat")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x402FA0, run_ccc=False)  # gettok
        func = cfg.functions[0x402FA0]
        dec = proj.analyses.Decompiler(func, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # check for incorrect branch conditions, which was a result of the bug in the original implementation of
        # Dephication.
        for m in re.finditer(r"!(v\d+) & (v\d+)", dec.codegen.text):
            vvar1, vvar2 = m.group(1), m.group(2)
            if vvar1 == vvar2:
                assert False, f"Found an always-false branch condition (!{vvar1} & {vvar2}) in the decompiled code."


if __name__ == "__main__":
    unittest.main()

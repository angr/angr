# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
from unittest import TestCase, main

import angr
from angr.ailment.expression import Phi
from angr.ailment.statement import Assignment
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestEntryPhiArg(TestCase):
    def test_smoke(self):
        p = angr.Project(os.path.join(test_location, "x86_64/dwdiff"))
        p.analyses.CFGFast(normalize=True)
        clinic = p.analyses.Clinic(p.kb.functions["doDiffInternal"])
        assert clinic.graph is not None
        (entry_block,) = (b for b in clinic.graph if b.addr == clinic.function.addr)
        assert any(
            isinstance(stmt, Assignment)
            and isinstance(stmt.src, Phi)
            and any(src is None for src, _ in stmt.src.src_and_vvars)
            for stmt in entry_block.statements
        )


if __name__ == "__main__":
    main()

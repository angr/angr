#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest
from collections import Counter

from angr.analyses.decompiler.edits import rename_variable
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")

# a local variable declaration in a decompiled function body: "    <type> name;  // ..."
DECL_RE = re.compile(r"^\s{4}[A-Za-z_][\w *]*?\*?\s*(\w+);\s*//", re.MULTILINE)


class TestRepeatedDecompilation(unittest.TestCase):
    """Decompiling one function twice in the same process must give the same answer.

    Both directions used to fail: the first run stored its own inferred prototype on the function and
    its semantic variable names in ``kb.dec_variables``, and the second run read both back as if they
    were facts, which changed the output and handed a name out twice.
    """

    ADDR = 0x409B60

    def _project(self):
        binary = os.path.join(test_location, "x86_64", "gzip_gcc13.3.0_O2")
        proj, _ = load_project_with_scoped_cfg(
            binary, self.ADDR, project_kwargs={"auto_load_libs": False}, include_plt=True
        )
        return proj, proj.kb.functions[self.ADDR]

    def _decompile_twice(self) -> list[str]:
        proj, func = self._project()
        texts = []
        for _ in range(2):
            dec = proj.analyses.Decompiler(func, preset="full", use_cache=False, update_cache=False)
            assert dec.codegen is not None
            texts.append(dec.codegen.text)
        return texts

    def test_repeated_decompilation_is_stable(self):
        first, second = self._decompile_twice()
        assert first == second

    def test_repeated_decompilation_keeps_variable_names_unique(self):
        _, second = self._decompile_twice()
        duplicated = sorted(name for name, count in Counter(DECL_RE.findall(second)).items() if count > 1)
        assert duplicated == []

    def test_user_renames_survive_redecompilation(self):
        """Resetting the automatic names between runs must not touch a name the user picked."""
        proj, func = self._project()
        proj.analyses.Decompiler(func, preset="full")

        # pick a semantically named local: those are exactly the ones the automatic reset clears
        rename_variable(proj, func, "idx", "picked_by_user")

        dec = proj.analyses.Decompiler(func, preset="full", regen_clinic=True)
        assert dec.codegen is not None
        names = DECL_RE.findall(dec.codegen.text)
        assert names.count("picked_by_user") == 1
        assert "picked_by_user1" not in names
        assert sorted(n for n, c in Counter(names).items() if c > 1) == []


if __name__ == "__main__":
    unittest.main()

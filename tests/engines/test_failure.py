#!/usr/bin/env python3
from __future__ import annotations

import unittest

from angr.engines.failure import is_failure_jumpkind

# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use


class TestIsFailureJumpkind(unittest.TestCase):
    def test_the_jumpkinds_the_engine_refuses_to_step(self):
        for jumpkind in ("Ijk_EmFail", "Ijk_MapFail", "Ijk_SigSEGV", "Ijk_SigFPE", "Ijk_SigTRAP", "Ijk_SigBUS"):
            assert is_failure_jumpkind(jumpkind), jumpkind

    def test_the_jumpkinds_it_steps(self):
        for jumpkind in ("Ijk_Boring", "Ijk_Call", "Ijk_Ret", "Ijk_FakeRet", "Ijk_Exit", "Ijk_NoDecode", None):
            assert not is_failure_jumpkind(jumpkind), jumpkind


if __name__ == "__main__":
    unittest.main()

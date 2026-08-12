#!/usr/bin/env python3
from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

import angr
from angr.analyses.decompiler.decompiler import Decompiler
from tests.common import bin_location

# sub_4111a0 has two duplicated subgraphs whose starting blocks the merge
# machinery clones without splitting; the clone compares equal to the block it
# replaces, which used to make the bookkeeping re-key delete the entry it had
# just written.
GZIP_BIN = os.path.join(bin_location, "tests", "x86_64", "gzip_gcc13.3.0_O2")
GZIP_FUNC = 0x4111A0


class TestDuplicationReverter(TestCase):
    def test_merging_a_cloned_start_block_does_not_raise(self):
        # A pass that raises is not a local failure: the Decompiler catches it and
        # retries the whole function with the *basic* preset, which drops every
        # optimization pass -- so one KeyError deep inside the deduplicator
        # silently costs the function all of its decompilation quality.
        proj = angr.Project(GZIP_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(addr=GZIP_FUNC)
        assert func is not None

        dec = proj.analyses[Decompiler](func, cfg=cfg.model, preset="full")
        assert not dec.errors, [e.format() for e in dec.errors]
        assert dec.codegen is not None and dec.codegen.text is not None


if __name__ == "__main__":
    unittest.main()

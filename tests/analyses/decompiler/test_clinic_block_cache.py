# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
from unittest import TestCase, main

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestClinicBlockCache(TestCase):
    def test_initial_block_cache_is_released_after_graph_construction(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text
        # the converted blocks are owned by the AIL graph; the lookup table must not pin them for the whole pipeline
        assert dec.clinic._blocks_by_addr_and_size is None


if __name__ == "__main__":
    main()

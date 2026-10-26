#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

from angr.utils.loader import is_in_readonly_section
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "armel")


class TestOverlappingBssConstDeref(unittest.TestCase):
    def test_globals_in_bss_overlapping_a_readonly_section_are_not_folded(self):
        # u-boot maps .bss over .rel.dyn. tftp_send switches on tftp_state, a .bss global whose address also lies
        # inside the read-only .rel.dyn section; folding that load into relocation bytes turned the switch's bounds
        # check into a constant and lost every case.
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "decbench_uboot_O2_noinline_stripped"),
            0x608750BC,
            window=0x300,
            expand_call_tree=False,
        )
        tftp_state = 0x6089DCB0
        assert proj.loader.find_section_containing(tftp_state).name == ".rel.dyn"
        assert not is_in_readonly_section(proj, tftp_state)

        dec = proj.analyses.Decompiler(cfg.functions[0x608750BC], cfg=cfg, fail_fast=True)

        assert not dec.structuring_failures
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "g_6089dcb0" in text
        assert "switch (" in text
        for s in ("File too large", "File has bad magic", "Option Negotiation Failed", "windowsize%c%d%c"):
            assert s in text


if __name__ == "__main__":
    unittest.main()

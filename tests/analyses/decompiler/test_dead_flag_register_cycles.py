#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestDeadFlagRegisterCycles(unittest.TestCase):
    def test_fpscr_updates_in_a_loop_are_removed(self):
        # applyFlipOverAfterCrashModeToMotors() (betaflight, O0). Every vcmp writes FPSCR from the previous FPSCR
        # value; inside the loop the chain closes on itself through a phi, so each write has a "use" even though
        # nothing ever reads the flags. The cycle used to survive dead-assignment elimination.
        bin_path = os.path.join(test_location, "armel", "decbench_betaflight_STM32F405_O0_stripped.elf")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x8036BD9, window=0x400, expand_call_tree=False)

        dec = proj.analyses.Decompiler(cfg.functions[0x8036BD9], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert "fpscr" not in text
        assert "isnan" not in text and "isunordered" not in text
        # the real computation is still there
        assert text.count("for (") == 2
        assert "/ 100.0f" in text

#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests", "mips")


class TestResolvedTailJumps(unittest.TestCase):
    """
    MIPS `jr $t9` through a GOT pointer is an unresolved indirect jump in the CFG; the decompiler resolves its target to
    another function's start only after simplification. It must become a tail call, not a goto.
    """

    def test_tail_jumps_through_the_got_become_calls(self):
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "busybox"),
            0x405C34,
            extra_func_addrs=(0x405B20, 0x4059E0, 0x42C4B0),
            window=0x200,
            expand_call_tree=False,
        )

        # the GOT pointer is loaded in an earlier block; the arguments come from the callee's prototype
        dec = proj.analyses.Decompiler(cfg.functions[0x405C34], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "goto LABEL_0x405b20;" not in text
        assert "return sub_405b20(a0, a1, a2);" in text

        # the GOT pointer is loaded in the jump block; the callee does not return
        dec = proj.analyses.Decompiler(cfg.functions[0x4059E0], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "goto LABEL_0x42c4b0;" not in text
        assert "sub_42c4b0(" in text

    def test_stack_arguments_of_a_tail_call_after_the_delay_slot(self):
        # the epilogue's `addiu $sp, $sp, 0x30` sits in the delay slot of `jr $t9`; the fifth argument is the caller's
        # own fifth argument
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "busybox"),
            0x407270,
            extra_func_addrs=(0x407210,),
            window=0x200,
            expand_call_tree=False,
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x407270], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "return sub_407210(a0, a1, a2, a3, a4);" in dec.codegen.text

    def test_tail_calls_into_a_lowered_switch_keep_the_switch_variable(self):
        proj, cfg = load_project_with_scoped_cfg(
            os.path.join(test_location, "busybox"),
            0x4C4C14,
            extra_func_addrs=(0x4C2C00,),
            window=0x400,
            expand_call_tree=False,
        )
        dec = proj.analyses.Decompiler(cfg.functions[0x4C4C14], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "return sub_4c2c00(" in text
        switch_vars = re.findall(r"switch \((v\d+)\)", text)
        assert len(switch_vars) == 1
        assert f"{switch_vars[0]} = *iter;" in text


if __name__ == "__main__":
    unittest.main()

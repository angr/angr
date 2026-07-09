#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr


class TestSSAStackPhiSizeConflict(unittest.TestCase):
    """
    A stack slot may reach a join point with definitions of different sizes, e.g., a 4-byte definition on one path and
    a 1-byte partial write on another path. The narrow definition is fully contained within the wide variable, so a phi
    node for the full-width variable must still be generated; otherwise the variable is dropped from the SSA state and
    a later wide use has no reaching definition, which raises a KeyError during SSA rewriting under fail_fast.

    The blob below is the machine code of a single 32-bit function (from a real binary) that exhibits this pattern:
    stack slot [ebp-0x1c] is written 4 bytes near the top, only 1 byte on a later path, and read 4 bytes after the join.
    """

    # 32-bit function that writes [ebp-0x1c] as 4 bytes and (on another path) as 1 byte, then reads it as 4 bytes.
    FUNC_BYTES = bytes.fromhex(
        "558bec83ec40a100f1490033c58945fc53568b750833db8975c48b41045785c0741a8b481885c975038d481c518d4dcc"
        "e8f4b4fdff8bfb33db43eb1c33c08d7de4ab6a02ababab8d45e4895df4c745f80f000000885de45f508bcee87db4fdff"
        "85ff0f848d0000008b4df883f90f7676803d9056490000743c8b55e48b7df44703fa8d420103c18945c88d420803c183"
        "e0f88bd08bc83bf876028bf83955c877038b4dc8515750ff75e4e88ac905008b4df883c4108d41018b4de48945c8894d"
        "c43d0010000072158d45c8508d45c450e80b86fdff8b45c859598b4dc45051e87855000059598365f400c745f80f0000"
        "00c645e40085db74088d4dcce85fc2fdff8b4dfc8bc65f5e33cd5be87c500000c9c20400"
    )
    BASE = 0x428F21

    def test_stack_slot_conflicting_def_sizes_at_join(self):
        proj = angr.load_shellcode(self.FUNC_BYTES, "x86", load_address=self.BASE, start_offset=0)
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[self.BASE])
        proj.analyses.CompleteCallingConventions()
        func = cfg.functions[self.BASE]
        # fail_fast=True: this raised KeyError before the phi-placement fix.
        dec = proj.analyses.Decompiler(func, cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None


if __name__ == "__main__":
    unittest.main()

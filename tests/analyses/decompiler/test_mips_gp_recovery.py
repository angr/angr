#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses import CFGFast, Decompiler
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# A MIPS prologue builds $gp from a `lui`/`addiu` pair, and CFGFast records the result in
# func.info["gp"]. These fixtures are PIC executables whose .got starts at a known address, so
# the $gp every function should receive is .got + 0x7ff0.
GP_OF = {
    "mips/argc_decide": 0x418860,
    "mips/argv_test": 0x418920,
    "mips/allcmps": 0x418A10,
    "mips/test_ioctl": 0x419010,
    "mips/manysum": 0x4189B0,
    "mips/argc_symbol": 0x418950,
    "mips/fauxware": 0x418CE0,
    "mipsel/fauxware": 0x418CA0,
}
# In these the `lui $gp` sits in a branch delay slot, so it is the last instruction of its
# block and the completing `addiu` is in the next one: on the fall-through for
# deregister_tm_clones, on the taken path for frame_dummy.
DELAY_SLOT_FUNCTIONS = {
    "mips/argc_decide": {"deregister_tm_clones": 0x4005B0, "frame_dummy": 0x400674},
}


class TestMipsFunctionGp(unittest.TestCase):
    def test_gp_is_the_value_the_prologue_computes(self):
        """
        Every function that gets a $gp gets the one its prologue computes, not a half-built one.

        A half-built value (a `lui` without its `addiu`, or one derived from an unknown incoming
        $gp) is not the binary's $gp, and `RewriteMipsGpLoads` resolves every $gp-relative load
        through it.
        """
        for name, gp in GP_OF.items():
            with self.subTest(binary=name):
                proj = angr.Project(os.path.join(test_location, name), auto_load_libs=False)
                cfg = proj.analyses[CFGFast].prep()(data_references=True, normalize=True)
                wrong = {
                    f.name: hex(f.info["gp"])
                    for f in cfg.functions.values()
                    if not (f.is_simprocedure or f.is_plt or f.is_alignment)
                    and f.info.get("gp") is not None
                    and f.info["gp"] != gp
                }
                assert not wrong, f"{name}: functions with a $gp other than {gp:#x}: {wrong}"

    def test_a_delay_slot_lui_does_not_lose_the_function(self):
        """
        A $gp whose `lui` is in a branch delay slot still decompiles.

        The `lui` is the last instruction of its block and its `addiu` is in the next one, so the
        function must get the full value, not the high half, and still decompile without errors.
        """
        for name, funcs in DELAY_SLOT_FUNCTIONS.items():
            proj = angr.Project(os.path.join(test_location, name), auto_load_libs=False)
            cfg = proj.analyses[CFGFast].prep()(data_references=True, normalize=True)
            for func_name, addr in funcs.items():
                with self.subTest(binary=name, function=func_name):
                    func = cfg.functions[addr]
                    assert func.name == func_name
                    assert func.info.get("gp") == GP_OF[name]
                    dec = proj.analyses[Decompiler].prep()(func, cfg=cfg.model)
                    assert not dec.errors, f"{func_name} recorded {len(dec.errors)} error(s): {dec.errors[0].format()}"
                    assert dec.codegen is not None, f"Failed to decompile {func!r}."

    def test_a_finished_sequence_is_not_run_twice(self):
        """
        Following a sequence past the end of its block does not execute any of it a second time.

        In mipsel/busybox the block at 0x430d60 holds `lui $gp` and `addiu $gp` and ends there,
        because the CFG also has an entry at 0x430d68, the `addu $gp, $gp, $t9` that completes the
        sequence. Executing one instruction past the last write already runs that `addu`, so
        starting the continuation at 0x430d68 would run it again and add `$t9` twice.
        """
        proj = angr.Project(os.path.join(test_location, "mipsel", "busybox"), auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(data_references=True, normalize=True)
        assert cfg.functions[0x430D60].info.get("gp") == 0x4CFAD0


if __name__ == "__main__":
    unittest.main()

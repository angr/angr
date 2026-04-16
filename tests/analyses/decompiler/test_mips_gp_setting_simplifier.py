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


class TestMipsGpSettingSimplifier(unittest.TestCase):
    def test_mipsel_fauxware_no_gp_setting(self):
        """
        Test that $gp-setting statements are removed from decompiled MIPS functions.

        In MIPS binaries, the compiler emits instructions at the start of each function to set the
        $gp register (global pointer). These instructions are an implementation detail and should
        not appear in the decompiled output.
        """
        bin_path = os.path.join(test_location, "mipsel", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["main"]
        gp_value = func.info.get("gp")
        assert gp_value is not None, "Function should have a gp value"

        dec = proj.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, f"Failed to decompile function {func!r}."
        code = dec.codegen.text
        assert code is not None

        # The GP value (0x418ca0 = 4295840) should not appear in the decompiled output
        assert str(gp_value) not in code, (
            f"GP value {gp_value} ({hex(gp_value)}) should not appear in decompiled output.\nDecompiled code:\n{code}"
        )
        assert hex(gp_value) not in code, (
            f"GP value {hex(gp_value)} should not appear in decompiled output.\nDecompiled code:\n{code}"
        )

        # Basic sanity: the decompiled output should still contain expected function calls
        assert "puts(" in code
        assert "read(" in code
        assert "authenticate(" in code

    def test_mipsel_busybox_no_gp_setting(self):
        """
        Test that PIC-style $gp-setting statements (gp = t9 + offset) are removed from decompiled
        MIPS functions. In PIC code the GP computation is not fully constant-propagated because it
        depends on t9 (the function address at call time).
        """
        bin_path = os.path.join(test_location, "mipsel", "busybox")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["main"]
        gp_value = func.info.get("gp")
        assert gp_value is not None, "Function should have a gp value"

        dec = proj.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, f"Failed to decompile function {func!r}."
        code = dec.codegen.text
        assert code is not None

        # The GP computation should not appear in the decompiled output.
        # The PIC pattern looks like: v0 = <offset> + vvar_5{r108|4b}
        assert "vvar_" not in code, (
            f"GP computation (t9 + offset) should not appear in decompiled output.\nDecompiled code:\n{code}"
        )

        # Basic sanity
        assert "lbb_prepare(" in code


if __name__ == "__main__":
    unittest.main()

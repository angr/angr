# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import logging
import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

l = logging.Logger(__name__)


class TestJumpkindIntrinsics(unittest.TestCase):
    """
    Regression tests for issue #8: unsupported jumpkinds (int3 -> Ijk_SigTRAP, int 0x2c ->
    Ijk_Sys_int) must never leak the internal "[D] Unsupported jumpkind ..." / "[D] syscall()()"
    diagnostic strings into the emitted C, and int3/Ijk_SigTRAP should map to __debugbreak().
    """

    # devinv.dll, stored under its SHA256 name in the binaries repo.
    BIN = os.path.join(
        test_location, "x86_64", "windows", "ddc2b4cbf6ac841524375cdf82b93b9948f8ea09bbf6e8bf3410e6bc410a9d95"
    )

    def _decompile(self, addr: int, window: int = 0x600) -> str:
        if not os.path.isfile(self.BIN):
            self.skipTest(f"missing test binary: {self.BIN}")
        proj = angr.Project(self.BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, regions=[(addr, addr + window)])
        func = cfg.functions.get_by_addr(addr)
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def _assert_no_diagnostic_leak(self, text: str) -> None:
        assert "[D] " not in text, "internal '[D] ' diagnostic marker leaked into emitted C"
        assert "Unsupported jumpkind" not in text, "'Unsupported jumpkind' diagnostic leaked into emitted C"

    def test_sigtrap_debugbreak_not_leaked(self):
        # sub_18001BC6C ends multiple paths in int3 (Ijk_SigTRAP / __debugbreak()).
        text = self._decompile(0x18001BC6C)
        self._assert_no_diagnostic_leak(text)
        # (b): int3 / Ijk_SigTRAP must be lowered to the __debugbreak() intrinsic.
        assert "__debugbreak(" in text, "int3/Ijk_SigTRAP was not lowered to __debugbreak()"

    def test_syscall_not_leaked(self):
        # sub_1800300C0 contains an int 0x2c (Ijk_Sys_int) path that previously rendered as
        # "[D] syscall()()" in the output.
        text = self._decompile(0x1800300C0)
        self._assert_no_diagnostic_leak(text)


if __name__ == "__main__":
    unittest.main()

# pylint:disable=missing-class-docstring,missing-function-docstring,no-self-use
"""
Regression tests for Windows Control-Flow-Guard (CFG) dispatch modeling.

CFG-instrumented binaries compile every indirect call as ``mov rax, <target>; call __guard_dispatch_icall``. The
``__guard_dispatch_icall`` entry point is a trivial thunk that just ``jmp``s to the real ``jmp rax`` dispatcher, so
CFGFast resolves the call to it as an ordinary direct call.

The fix is in ``CFGFast._propagate_key_func_info_to_jump_thunks``, which copies the ``jmp_rax`` marker (and any other
key-function ``info``) from the real dispatcher onto the trivial jump thunk.
"""

from __future__ import annotations

import os
import re
import unittest

import angr
from angr.analyses import Decompiler
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

BIN_PATH = (
    os.path.join(
        test_location, "x86_64", "windows", "ddc2b4cbf6ac841524375cdf82b93b9948f8ea09bbf6e8bf3410e6bc410a9d95"
    )
)

GUARD_DISPATCH_THUNK = 0x180124010
NORMAL_FUNC = 0x18000A7F8


class TestCFGuardDispatch(unittest.TestCase):
    def test_guard_dispatch_marker_propagated_to_jump_thunk(self):
        """CFGFast must copy the jmp_rax marker from the real dispatcher onto the trivial jump thunk."""
        bin_path = BIN_PATH
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        thunk = cfg.functions.function(GUARD_DISPATCH_THUNK)
        assert thunk is not None
        # the thunk is a single `jmp <dispatcher>` and must inherit the dispatcher's jmp_rax marker
        assert thunk.info.get("jmp_rax") is True, "jmp_rax was not propagated to the guard dispatch thunk"

        # a normal (non-thunk) function must NOT be marked
        normal = cfg.functions.function(NORMAL_FUNC)
        assert normal is not None
        assert normal.info.get("jmp_rax") is not True

    def test_cfguard_dispatch_calls_are_decollapsed(self):
        """After the fix, indirect calls resolve to distinct real targets instead of one bogus sub_<thunk>()."""
        bin_path = BIN_PATH
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg)

        func = cfg.functions.function(NORMAL_FUNC)
        assert func is not None
        d = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert d.codegen is not None
        text = d.codegen.text

        # The guard dispatch thunk must NOT appear as a direct callee. Before the fix every indirect call collapsed
        # into a single argument-less `sub_180124010()`.
        assert "sub_180124010" not in text, "guard dispatch thunk still modeled as a direct call"

        # The previously-collapsed indirect calls must now resolve to several DISTINCT real targets (the per-call
        # vtable/function-pointer globals), proving the single-target collapse is gone.
        targets = set(re.findall(r"(g_18016[0-9a-f]+)\(", text))
        assert len(targets) >= 2, f"indirect calls did not de-collapse into distinct targets: {sorted(targets)}"

        # The indirect calls must also carry their recovered call-site arguments (not be collapsed to 0-arg).
        # g_180165170 corresponds to IDA's qword_180165170(v15, v16, 1024) -- a 3-argument call.
        m = re.search(r"g_180165170\(([^)]*)\)", text)
        assert m is not None, "expected indirect call through g_180165170 was not recovered"
        args = m.group(1).strip()
        assert args.count(",") >= 1, f"call-site arguments not recovered for g_180165170(...): {args!r}"


if __name__ == "__main__":
    unittest.main()

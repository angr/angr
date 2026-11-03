#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import struct
import unittest

import angr
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction

CALLER = 0x1000
CALLEE = 0x1100


class TestFunctionObjectCalleeCC(unittest.TestCase):
    def test_callsite_args_for_function_object_callee(self):
        # lea rdi, [rsp+0x20]; mov esi, 5; call CALLEE; add rsp, 0x28; ret
        code = bytes.fromhex("4883ec28488d7c2420be05000000") + b"\xe8" + struct.pack("<i", CALLEE - 0x1013)
        code += bytes.fromhex("4883c428c3")
        proj = angr.load_shellcode(code.ljust(0x200, b"\xcc"), "AMD64", load_address=CALLER)
        # no prototype: a guessed one
        proj.hook(CALLEE, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](display_name="callee"), replace=True)
        cfg = proj.analyses.CFGFast(function_starts=[CALLER], normalize=True, show_progressbar=False)

        # VM deobfuscation builds its function with the callee Function object as the call target
        del proj.kb.functions[CALLER]
        func = proj.kb.functions.function(CALLER, create=True)
        callee = proj.kb.functions.function(CALLEE, create=True)
        callee.is_simprocedure = True
        callee.calling_convention = proj.factory.cc()
        callee.prototype = None
        b0, b1 = proj.factory.block(CALLER).codenode, proj.factory.block(0x1013).codenode
        func.call_to(b0, callee, b1)
        func.return_from_call(callee, b1)
        func.startpoint = b0
        func.normalized = True
        func.calling_convention = proj.factory.cc()
        func.set_prototype(
            None,
            SimTypeFunction([], SimTypeBottom(label="void")).with_arch(proj.arch),
            source=PrototypeSource.SIMPROC,
        )

        dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None
        assert "callee(&v0, 5);" in dec.codegen.text, dec.codegen.text


if __name__ == "__main__":
    unittest.main()

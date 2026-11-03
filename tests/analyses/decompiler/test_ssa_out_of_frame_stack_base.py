#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.sim_variable import SimStackVariable


class TestSSAOutOfFrameStackBase(unittest.TestCase):
    """
    An inlined strcmp addresses a stack buffer through a pointer difference, ``rdi = &buf - &str`` and ``[rax + rdi]``
    with ``rax = &str``. ``rdi`` is a "stack pointer" far below the frame; it must not become the base of one stack
    variable spanning everything up to ``buf``.
    """

    #   sub    rsp, 0x58
    #   mov    [rsp+0x48], rcx
    #   mov    [rsp+0x50], rdx
    #   mov    qword [rsp+0x20], 0
    #   mov    eax, 0x25af8
    #   lea    rdi, [rsp+0x10]
    #   sub    rdi, rax
    #   movzx  ecx, byte [rax]
    #   movzx  edx, byte [rax+rdi]
    #   sub    ecx, edx
    #   jne    done
    #   inc    rax
    # loop:
    #   movzx  ecx, byte [rax]
    #   movzx  edx, byte [rax+rdi]
    #   sub    ecx, edx
    #   jne    done
    #   inc    rax
    #   test   edx, edx
    #   jne    loop
    # done:
    #   mov    eax, ecx
    #   add    rax, [rsp+0x48]
    #   add    rax, [rsp+0x50]
    #   add    rax, [rsp+0x20]
    #   add    rsp, 0x58
    #   ret
    FUNC_BYTES = bytes.fromhex(
        "4883ec5848894c2448488954245048c744242000000000b8f85a0200488d7c24104829c70fb6080fb6143829d1751548ffc0"
        "0fb6080fb6143829d1750748ffc085d275ee89c84803442448480344245048034424204883c458c3"
    )
    BASE = 0x20000

    def test_pointer_difference_does_not_span_frame(self):
        proj = angr.load_shellcode(self.FUNC_BYTES, "AMD64", load_address=self.BASE, start_offset=0)
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[self.BASE])
        func = cfg.functions[self.BASE]
        dec = proj.analyses.Decompiler(func, cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None

        stack_vars = [
            v for v in proj.kb.dec_variables[func.addr].get_variables() if isinstance(v, SimStackVariable)
        ]
        assert stack_vars
        assert max(v.size or 0 for v in stack_vars) <= 0x58, dec.codegen.text
        # the first, peeled comparison reads buf[0] at rsp+0x10 (bp-0x48)
        assert any(v.offset == -0x48 for v in stack_vars), dec.codegen.text


if __name__ == "__main__":
    unittest.main()

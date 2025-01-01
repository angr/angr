#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.propagator.vex_vars import VEXReg

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestFCP(unittest.TestCase):
    def test_lwip_udpecho_bm(self):
        bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
        p = angr.Project(bin_path, auto_load_libs=False)
        cfg = p.analyses.CFG()

        func = cfg.functions[0x23C9]
        prop = p.analyses.FastConstantPropagation(func)

        assert len(prop.replacements) > 0

    def test_register_propagation_across_calls(self):
        call_targets = [
            "syscall",
            "call _0",  # Resolved
            "call rdi",  # TOP
            "call qword ptr [0xBAD]",  # Unresolved
        ]

        for target in call_targets:
            p = angr.load_shellcode(
                f"""
            _0:
                mov rcx, 0x12345678
                mov rbp, 0xFEDCBA90
            _11:
                {target}
                mov rax, rcx
                mov rdi, rbp
                ret
            """,
                "AMD64",
            )
            cfg = p.analyses.CFG()
            prop = p.analyses.FastConstantPropagation(func=cfg.functions[0])
            regs_replaced = {
                p.arch.register_names[var.offset]: val
                for codeloc, replacements in prop.replacements.items()
                if codeloc.block_addr >= 0x11
                for var, val in replacements.items()
                if isinstance(var, VEXReg)
            }
            assert "rax" not in regs_replaced  # caller saved
            assert regs_replaced["rdi"] == 0xFEDCBA90  # callee saved


if __name__ == "__main__":
    unittest.main()

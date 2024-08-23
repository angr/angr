#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.propagator.vex_vars import VEXReg

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestConstantpropagation(unittest.TestCase):
    def test_libc_x86(self):
        # disabling auto_load_libs increases the execution time.
        p = angr.Project(os.path.join(test_location, "i386", "libc-2.27-3ubuntu1.so.6"), auto_load_libs=True)
        dl_addr = p.loader.find_symbol("_dl_addr").rebased_addr
        cfg = p.analyses.CFGFast(regions=[(dl_addr, dl_addr + 4096)])
        func = cfg.functions["_dl_addr"]

        rtld_global_sym = p.loader.find_symbol("_rtld_global")
        assert rtld_global_sym is not None
        _rtld_global_addr = rtld_global_sym.rebased_addr

        base_addr = 0x998F000
        state = p.factory.blank_state()
        for addr in range(0, 0 + 0x1000, p.arch.bytes):
            state.memory.store(
                _rtld_global_addr + addr, base_addr + addr, size=p.arch.bytes, endness=p.arch.memory_endness
            )

        prop = p.analyses.Propagator(func=func, base_state=state)
        # import pprint
        # pprint.pprint(prop.replacements)
        assert len(prop.replacements) > 0

    def test_lwip_udpecho_bm(self):
        bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
        p = angr.Project(bin_path, auto_load_libs=False)
        cfg = p.analyses.CFG(data_references=True)

        func = cfg.functions[0x23C9]
        state = p.factory.blank_state()
        prop = p.analyses.Propagator(func=func, base_state=state)

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
            prop = p.analyses.Propagator(func=cfg.functions[0], only_consts=True)
            regs_replaced = {
                p.arch.register_names[var.offset]: val
                for codeloc, replacements in prop.replacements.items()
                if codeloc.block_addr >= 0x11
                for var, val in replacements.items()
                if isinstance(var, VEXReg)
            }
            assert "rax" not in regs_replaced  # caller saved
            assert regs_replaced["rdi"].concrete_value == 0xFEDCBA90  # callee saved


if __name__ == "__main__":
    unittest.main()

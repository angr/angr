#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.fcp.fcp import SV, FastConstantPropagation, FCPState
from angr.analyses.propagator.vex_vars import VEXReg
from angr.codenode import HookNode
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

    def test_hook_nodes_are_not_lifted(self):
        # every SimProcedure stub is a function whose graph is a single hook node
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        p = angr.Project(bin_path, auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)

        funcs = [func for func in cfg.functions.values() if any(isinstance(node, HookNode) for node in func.graph)]
        assert funcs

        for func in funcs:
            prop = p.analyses.FastConstantPropagation(func)
            assert not prop.replacements

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

    def test_merge_states_meet(self):
        a = FCPState()
        a.register_written(16, 8, 1)
        a.register_written(24, 8, 2)
        a.stack_written(8, 8, 3)
        a.sp_value = 0x10
        b = a.copy()
        b.register_written(24, 8, 5)
        b.sp_value = 0x20

        assert FastConstantPropagation._merge_states([a, a]) is a
        merged = FastConstantPropagation._merge_states([a, b])
        assert merged.regs == {16: SV(1, 64)}
        assert merged.stack == {8: SV(3, 64)}
        assert merged.sp_value == 0x20
        # the meet of a state with a state it subsumes is that state
        assert FastConstantPropagation._merge_states([a, merged]) is merged

    def test_skipped_blocks_pass_states_through(self):
        p = angr.load_shellcode(
            """
            mov rcx, 0x1234
            test rdi, rdi
            je _else
            mov rcx, 0x5678
            jmp _join
        _else:
            mov rdx, 1
            jmp _join
        _join:
            mov rax, rcx
            ret
            """,
            "AMD64",
        )
        cfg = p.analyses.CFG()
        func = cfg.functions[0]
        entry = func.get_node(0)
        join = next(node for node in func.graph if func.graph.in_degree(node) == 2)

        def rcx_reads(prop):
            return {
                val
                for codeloc, replacements in prop.replacements.items()
                if codeloc.block_addr == join.addr
                for var, val in replacements.items()
                if isinstance(var, VEXReg) and var.offset == p.arch.registers["rcx"][0]
            }

        # both branches processed: rcx disagrees at the join
        assert rcx_reads(p.analyses.FastConstantPropagation(func)) == set()
        # branches skipped: the entry state flows through them unchanged
        assert rcx_reads(p.analyses.FastConstantPropagation(func, blocks={entry, join})) == {0x1234}


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.calling_conventions import (
    SimCCCdecl,
    SimCCSystemVAMD64,
    default_cc,
)
from angr.engines.pcode.cc import register_pcode_arch_default_cc
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestFactCollector(unittest.TestCase):
    @staticmethod
    def _collect_shellcode_facts(code: bytes, arch: str = "amd64"):
        base_addr = 0x400000
        project = angr.load_shellcode(code, arch=arch, load_address=base_addr)
        cfg = project.analyses.CFGFast(
            normalize=True,
            regions=[(base_addr, base_addr + len(code))],
            function_starts=[base_addr],
            start_at_entry=False,
            symbols=False,
            force_smart_scan=False,
        )
        return project.analyses.FunctionFactCollector(cfg.kb.functions[base_addr])

    def test_stack_canary_comparison_is_not_a_return_value(self):
        prefix = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "31c0"  # xor eax, eax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
        )
        void_tail = bytes.fromhex(
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        for operation in ("64482b042528000000", "644833042528000000"):  # sub/xor rax, qword ptr fs:[0x28]
            with self.subTest(operation=operation):
                facts = self._collect_shellcode_facts(prefix + bytes.fromhex(operation) + void_tail)
                self.assertIsNone(facts.retval_size)

    def test_x86_stack_canary_comparison_is_not_a_return_value(self):
        code = bytes.fromhex(
            "83ec0c"  # sub esp, 0xc
            "65a114000000"  # mov eax, dword ptr gs:[0x14]
            "89442404"  # mov dword ptr [esp + 4], eax
            "31c0"  # xor eax, eax
            "8b442404"  # mov eax, dword ptr [esp + 4]
            "652b0514000000"  # sub eax, dword ptr gs:[0x14]
            "7504"  # jne stack_chk_fail
            "83c40c"  # add esp, 0xc
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        facts = self._collect_shellcode_facts(code, arch="x86")

        self.assertIsNone(facts.retval_size)

    def test_stack_canary_comparison_preserves_real_return_value(self):
        prefix = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "31c0"  # xor eax, eax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
        )
        epilogue = bytes.fromhex("4883c418c3e800000000")  # add rsp, 0x18; ret; call stack_chk_fail

        cases = (
            ("750ab82a000000", 4),  # jne +10; mov eax, 42
            ("750f48b82a00000078563412", 8),  # jne +15; movabs rax, 0x123456780000002a
        )
        for return_code, expected_size in cases:
            with self.subTest(expected_size=expected_size):
                facts = self._collect_shellcode_facts(prefix + bytes.fromhex(return_code) + epilogue)
                self.assertEqual(facts.retval_size, expected_size)

    def test_tls_arithmetic_without_terminal_call_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "31c0"  # xor eax, eax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne alternate return
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
        )

        facts = self._collect_shellcode_facts(code)

        self.assertEqual(facts.retval_size, 8)

    @staticmethod
    def _pcode_cfg(code: bytes, function_starts: list[int], resolve_indirect_jumps: bool = False):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        register_pcode_arch_default_cc(arch)
        project = angr.load_shellcode(
            code,
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        project.simos.name = "Win16"
        cfg = project.analyses.CFGFast(
            function_starts=function_starts,
            regions=[(0, len(code))],
            start_at_entry=False,
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=resolve_indirect_jumps,
            indirect_calls_always_return=True,
        )
        return project, cfg

    def test_pcode_return_value_search_uses_fact_collector_depth(self):
        # mov ax, 7; four basic-block-ending jumps; ret
        project, cfg = self._pcode_cfg(bytes.fromhex("b80700" + "eb00" * 4 + "c3"), [0])
        function = cfg.functions[0]

        bounded_facts = project.analyses.FunctionFactCollector(function, max_depth=3)
        facts = project.analyses.FunctionFactCollector(function)

        self.assertIsNone(bounded_facts.retval_size)
        self.assertEqual(facts.retval_size, 2)

    def test_pcode_return_value_propagates_from_known_direct_callee(self):
        # call 0x10; ret; padding; mov ax, 7; ret
        code = bytes.fromhex("e80d00c3" + "90" * 12 + "b80700c3")
        project, cfg = self._pcode_cfg(code, [0, 0x10])
        leaf = cfg.functions[0x10]
        self.assertIsNone(project.analyses.FunctionFactCollector(cfg.functions[0]).retval_size)
        leaf_analysis = project.analyses.CallingConvention(leaf, cfg=cfg.model, collect_facts=True)
        self.assertIsNotNone(leaf_analysis.cc)
        self.assertIsNotNone(leaf_analysis.prototype)
        leaf.calling_convention = leaf_analysis.cc
        leaf.prototype = leaf_analysis.prototype

        wrapper_facts = project.analyses.FunctionFactCollector(cfg.functions[0])

        self.assertEqual(wrapper_facts.retval_size, 2)

    def test_pcode_return_value_follows_shared_tail_entry(self):
        # Both function starts jump to the same `mov ax, 7; ret` tail.
        code = bytes.fromhex("ba3412eb05ba7856eb00b80700c3")
        project, cfg = self._pcode_cfg(code, [0, 5])

        thunk_facts = project.analyses.FunctionFactCollector(cfg.functions[5])

        self.assertEqual(thunk_facts.retval_size, 2)

    def test_pcode_opaque_return_flow_is_indeterminate(self):
        for code in (bytes.fromhex("ffe3"), bytes.fromhex("ffd1c3")):  # jmp bx; call cx; ret
            with self.subTest(code=code.hex()):
                project, cfg = self._pcode_cfg(code, [0], resolve_indirect_jumps=True)

                facts = project.analyses.FunctionFactCollector(cfg.functions[0])

                self.assertIsNone(facts.retval_size)
                self.assertTrue(facts.retval_size_indeterminate)

        project, cfg = self._pcode_cfg(bytes.fromhex("c3"), [0])  # ret
        facts = project.analyses.FunctionFactCollector(cfg.functions[0])
        self.assertIsNone(facts.retval_size)
        self.assertFalse(facts.retval_size_indeterminate)

    def _run_fauxware(self, arch, function_and_cc_list):
        binary_path = os.path.join(test_location, arch, "fauxware")
        fauxware = angr.Project(binary_path, auto_load_libs=False)

        cfg = fauxware.analyses.CFG()

        for func_name, expected_cc in function_and_cc_list:
            authenticate = cfg.functions[func_name]
            ffc = fauxware.analyses.FunctionFactCollector(authenticate)

            cc_analysis = fauxware.analyses.CallingConvention(
                authenticate,
                cfg=cfg.model,
                analyze_callsites=True,
                input_args=ffc.input_args,
                retval_size=ffc.retval_size,
            )
            cc = cc_analysis.cc
            assert cc == expected_cc

    def test_fauxware_i386(self):
        self._run_fauxware("i386", [("authenticate", SimCCCdecl(archinfo.arch_from_id("i386")))])

    def test_fauxware_x86_64(self):
        amd64 = archinfo.arch_from_id("amd64")
        self._run_fauxware(
            "x86_64",
            [
                (
                    "authenticate",
                    SimCCSystemVAMD64(
                        amd64,
                    ),
                ),
            ],
        )

    def _check_caller_saved_excluded(self, arch_dir):
        """Helper: no caller-saved register offset may appear in callee_restored_regs."""

        binary_path = os.path.join(test_location, arch_dir, "fauxware")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG()

        cc_cls = default_cc(proj.arch.name, platform=proj.simos.name if proj.simos is not None else None)
        assert cc_cls is not None
        cc = cc_cls(proj.arch)

        caller_saved_offsets = set()
        for reg_name in cc.CALLER_SAVED_REGS:
            if reg_name in proj.arch.registers:
                caller_saved_offsets.add(proj.arch.registers[reg_name][0])
        assert caller_saved_offsets, "expected at least one caller-saved register"

        for func in cfg.functions.values():
            ffc = proj.analyses.FunctionFactCollector(func)
            callee_restored = ffc._analyze_endpoints_for_restored_regs()
            overlap = callee_restored & caller_saved_offsets
            assert not overlap, (
                f"{func.name} @ {hex(func.addr)}: caller-saved offsets {overlap} leaked into callee_restored_regs"
            )

    def test_caller_saved_regs_excluded_from_callee_restored_armel(self):
        """ARM: caller-saved regs (r0-r3, r12) must not appear in callee_restored_regs."""
        self._check_caller_saved_excluded("armel")


if __name__ == "__main__":
    unittest.main()

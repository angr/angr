#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import archinfo

import angr
from angr.calling_conventions import (
    SimCCCdecl,
    SimCCMicrosoftCdecl,
    SimCCStdcall,
    SimCCSystemVAMD64,
    default_cc,
)
from angr.rust import RUST_FLAVOR
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypeLongLong
from angr.utils.ssa import get_reg_offset_base
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

    def test_x86_extra_pop_from_returns(self):
        # `pop ecx; push ecx; ret` pops nothing beyond the return address
        self.assertEqual(self._collect_shellcode_facts(bytes.fromhex("5951c3"), arch="x86").extra_pop, 0)
        # ret 8
        self.assertEqual(self._collect_shellcode_facts(bytes.fromhex("c20800"), arch="x86").extra_pop, 8)

    def test_retval_from_callee_prototype_of_flavor(self):
        # caller: call callee; ret. callee: mov eax, 1; ret
        code = bytes.fromhex("e80b000000c3") + b"\xcc" * 10 + bytes.fromhex("b801000000c3")
        base_addr = 0x400000
        project = angr.load_shellcode(code, arch="amd64", load_address=base_addr)
        cfg = project.analyses.CFGFast(
            normalize=True,
            regions=[(base_addr, base_addr + len(code))],
            function_starts=[base_addr, base_addr + 0x10],
            start_at_entry=False,
            symbols=False,
            force_smart_scan=False,
        )
        caller, callee = cfg.kb.functions[base_addr], cfg.kb.functions[base_addr + 0x10]
        callee.calling_convention = SimCCSystemVAMD64(project.arch)
        callee.prototype = SimTypeFunction([], SimTypeInt()).with_arch(project.arch)
        # a non-default flavor knows the callee returns nothing
        callee.set_prototype(RUST_FLAVOR, SimTypeFunction([], None).with_arch(project.arch))
        self.assertEqual(project.analyses.FunctionFactCollector(caller).retval_size, 4)
        self.assertIsNone(project.analyses.FunctionFactCollector(caller, flavor=RUST_FLAVOR).retval_size)

    def test_complete_calling_conventions_writes_flavor_prototype(self):
        # caller: call callee; ret. callee: mov eax, 1; ret
        code = bytes.fromhex("e80b000000c3") + b"\xcc" * 10 + bytes.fromhex("b801000000c3")
        base_addr = 0x400000
        project = angr.load_shellcode(code, arch="amd64", load_address=base_addr)
        cfg = project.analyses.CFGFast(
            normalize=True,
            regions=[(base_addr, base_addr + len(code))],
            function_starts=[base_addr, base_addr + 0x10],
            start_at_entry=False,
            symbols=False,
            force_smart_scan=False,
        )
        caller, callee = cfg.kb.functions[base_addr], cfg.kb.functions[base_addr + 0x10]
        callee.calling_convention = SimCCSystemVAMD64(project.arch)
        callee.prototype = SimTypeFunction([], SimTypeInt()).with_arch(project.arch)
        callee.set_prototype(RUST_FLAVOR, SimTypeFunction([], None).with_arch(project.arch))
        caller.prototype = SimTypeFunction([SimTypeLongLong()], SimTypeLongLong()).with_arch(project.arch)
        c_repr = str(caller.prototype)
        # an empty entry (not a missing one, which falls back to C) asks CCA to analyze the function for the flavor
        caller.set_prototype(RUST_FLAVOR, None)
        project.analyses.CompleteCallingConventions(
            prioritize_func_addrs=[base_addr], skip_other_funcs=True, flavor=RUST_FLAVOR
        )
        flavor_proto = caller.get_prototype(RUST_FLAVOR)
        assert flavor_proto is not None and not flavor_proto.args and isinstance(flavor_proto.returnty, SimTypeBottom)
        assert str(caller.prototype) == c_repr

    def test_x86_extra_pop_of_tail_jump_thunk(self):
        # thunk at 0x400000: jmp 0x400010; target at 0x400010: mov eax, [esp+4]; ret 4
        code = bytes.fromhex("eb0e") + b"\xcc" * 14 + bytes.fromhex("8b442404c20400")
        base_addr = 0x400000
        target_addr = base_addr + 0x10
        project = angr.load_shellcode(code, arch="x86", load_address=base_addr)
        cfg = project.analyses.CFGFast(
            normalize=True,
            regions=[(base_addr, base_addr + len(code))],
            function_starts=[base_addr, target_addr],
            start_at_entry=False,
            symbols=False,
            force_smart_scan=False,
        )
        thunk = cfg.kb.functions[base_addr]
        target = cfg.kb.functions[target_addr]

        # a jmp is not a ret (which used to yield -4); without a calling convention, the target's ret 4 decides
        self.assertEqual(project.analyses.FunctionFactCollector(thunk).extra_pop, 4)

        # otherwise, the thunk pops whatever the target's calling convention pops
        proto = SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(project.arch)
        target.calling_convention = SimCCStdcall(project.arch)
        target.prototype = proto
        self.assertEqual(project.analyses.FunctionFactCollector(thunk).extra_pop, 4)
        target.calling_convention = SimCCMicrosoftCdecl(project.arch)
        self.assertEqual(project.analyses.FunctionFactCollector(thunk).extra_pop, 0)

    def test_x86_extra_pop_of_split_off_epilogue(self):
        # 0x400000: push ebx; jmp 0x400010. 0x400010 is its epilogue: pop ebx; ret 8. The epilogue is also called from
        # 0x400020 (push 1; push 2; call 0x400010; ret), so the CFG splits it off as a function. The jump is not a
        # tail call (ebx is still on the stack), so the epilogue's ret is the function's own.
        code = (
            bytes.fromhex("53eb0d")
            + b"\xcc" * 13
            + bytes.fromhex("5bc20800")
            + b"\xcc" * 12
            + bytes.fromhex("6a016a02e8e7ffffffc3")
        )
        base_addr = 0x400000
        project = angr.load_shellcode(code, arch="x86", load_address=base_addr)
        cfg = project.analyses.CFGFast(
            normalize=True,
            regions=[(base_addr, base_addr + len(code))],
            function_starts=[base_addr, base_addr + 0x10, base_addr + 0x20],
            start_at_entry=False,
            symbols=False,
            force_smart_scan=False,
        )
        func = cfg.kb.functions[base_addr]
        assert not func.endpoints_with_type["return"]
        self.assertEqual(project.analyses.FunctionFactCollector(func).extra_pop, 8)

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

    def test_s390x_float_constant_write_does_not_break_retval_size(self):
        # atan2 compares its argument against zero loaded by lzdr, which lifts to an 8-byte Put of an
        # Ity_F64 constant. The return-value size check masked such a constant against
        # 0xFFFF_FFFF_0000_0000, and a float constant carries a Python float.
        binary_path = os.path.join(test_location, "s390x", "libm.so.6")
        proj = angr.Project(binary_path, auto_load_libs=False)
        atan2 = proj.loader.find_symbol("atan2")
        assert atan2 is not None

        cfg = proj.analyses.CFGFast(
            normalize=True,
            regions=[(atan2.rebased_addr, atan2.rebased_addr + atan2.size)],
            function_starts=[atan2.rebased_addr],
            start_at_entry=False,
            symbols=False,
            force_smart_scan=False,
        )
        facts = proj.analyses.FunctionFactCollector(cfg.kb.functions[atan2.rebased_addr])

        self.assertEqual(facts.retval_size, 8)

    def test_overlapping_subregister_reads_are_one_input_arg(self):
        # mov al, ch; mov bx, cx; ret
        facts = self._collect_shellcode_facts(bytes.fromhex("88e86689cbc3"))
        # the lifter may model the reads as ch/cx or as narrowed rcx reads; either way, one argument
        assert len(facts.input_args) == 1
        arch = facts.project.arch
        assert get_reg_offset_base(arch.registers[facts.input_args[0].reg_name][0], arch) == arch.registers["rcx"][0]

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

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
from angr.codenode import BlockNode, FuncNode
from angr.sim_type import SimTypeBottom
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _TerminalFailure(angr.SimProcedure):
    NO_RET = True

    def run(self):
        self.exit(1)


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestFactCollector(unittest.TestCase):
    @staticmethod
    def _collect_shellcode(
        code: bytes,
        arch: str = "amd64",
        failure_name: str | None = None,
        reverse_entry_successors: bool = False,
    ):
        base_addr = 0x400000
        function_starts = [base_addr]
        failure_addr = base_addr + len(code) if failure_name is not None else None
        if failure_addr is not None:
            code += b"\xcc"
        project = angr.load_shellcode(code, arch=arch, load_address=base_addr)
        if failure_addr is not None:
            project.hook(failure_addr, _TerminalFailure(display_name=failure_name))
            function_starts.append(failure_addr)
        cfg = project.analyses.CFGFast(
            normalize=True,
            regions=[(base_addr, base_addr + len(code))],
            function_starts=function_starts,
            start_at_entry=False,
            symbols=False,
            force_smart_scan=False,
        )
        function = cfg.kb.functions[base_addr]
        if reverse_entry_successors:
            graph = function.transition_graph
            entry = function.startpoint
            outgoing_edges = list(graph.out_edges(entry, data=True))
            assert len(outgoing_edges) == 2
            for source, target, _ in outgoing_edges:
                graph.remove_edge(source, target)
            for source, target, data in reversed(outgoing_edges):
                graph.add_edge(source, target, **data)
        facts = project.analyses.FunctionFactCollector(function)
        return project, cfg, function, facts

    @classmethod
    def _collect_shellcode_facts(cls, code: bytes, arch: str = "amd64", failure_name: str | None = None):
        return cls._collect_shellcode(code, arch=arch, failure_name=failure_name)[3]

    @classmethod
    def _assert_shellcode_return_type(
        cls, code: bytes, expected_size: int | None, arch: str = "amd64", failure_name: str | None = None
    ):
        project, cfg, function, facts = cls._collect_shellcode(code, arch=arch, failure_name=failure_name)
        cc_analysis = project.analyses.CallingConvention(
            function,
            cfg=cfg.model,
            input_args=facts.input_args,
            retval_size=facts.retval_size,
        )
        assert cc_analysis.prototype is not None
        assert facts.retval_size == expected_size
        assert isinstance(cc_analysis.prototype.returnty, SimTypeBottom) is (expected_size is None)

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
                facts = self._collect_shellcode_facts(
                    prefix + bytes.fromhex(operation) + void_tail, failure_name="__stack_chk_fail"
                )
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

        facts = self._collect_shellcode_facts(code, arch="x86", failure_name="__stack_chk_fail")

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
                facts = self._collect_shellcode_facts(
                    prefix + bytes.fromhex(return_code) + epilogue, failure_name="__stack_chk_fail"
                )
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

    def test_canary_retval_and_guard_must_use_the_same_saved_slot(self):
        code = bytes.fromhex(
            "4883ec28"  # sub rsp, 0x28
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442418"  # mov qword ptr [rsp + 0x18], rax
            "48897c2408"  # mov qword ptr [rsp + 8], rdi
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "488b4c2418"  # mov rcx, qword ptr [rsp + 0x18]
            "64482b0c2528000000"  # sub rcx, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c428"  # add rsp, 0x28
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_canary_retval_and_guard_must_use_the_same_value_definition(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "488b4c2408"  # mov rcx, qword ptr [rsp + 8]
            "64482b0c2528000000"  # sub rcx, qword ptr fs:[0x28]
            "4885c9"  # test rcx, rcx
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_indexed_tls_address_is_not_a_stack_canary(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "48897c2408"  # mov qword ptr [rsp + 8], rdi
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b4328"  # sub rax, qword ptr fs:[rbx + 0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_unsaved_stack_value_is_not_a_stack_canary(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "48897c2408"  # mov qword ptr [rsp + 8], rdi
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_unrelated_terminal_call_is_not_a_stack_canary_failure(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "31c0"  # xor eax, eax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne panic_now
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call panic_now
        )

        self._assert_shellcode_return_type(code, 8, failure_name="panic_now")

    def test_canary_guard_must_control_stack_chk_fail_edge(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne alternate return
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "4883c418"  # alternate return: add rsp, 0x18
            "c3"  # ret
            "e800000000"  # unreachable call stack_chk_fail
        )
        project, _, function, _ = self._collect_shellcode(code, failure_name="__stack_chk_fail")
        check_node = function.startpoint
        assert isinstance(check_node, BlockNode)
        fake_call = BlockNode(check_node.addr + len(code) - 5, 5)
        function.transition_graph.add_edge(check_node, fake_call, type="transition", outside=False)
        function.transition_graph.add_edge(
            fake_call,
            FuncNode(check_node.addr + len(code)),
            type="call",
            outside=True,
        )

        facts = project.analyses.FunctionFactCollector(function)

        self.assertEqual(facts.retval_size, 8)

    def test_stack_chk_fail_edge_must_represent_a_canary_mismatch(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7405"  # je stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_fallthrough_stack_chk_fail_must_represent_a_canary_mismatch(self):
        prefix = (
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
        )
        suffix = (
            "e805000000"  # call stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
        )
        for branch, expected_size in (("7405", None), ("7505", 8)):  # je/jne successful return
            with self.subTest(branch=branch):
                self._assert_shellcode_return_type(
                    bytes.fromhex(prefix + branch + suffix),
                    expected_size,
                    failure_name="__stack_chk_fail",
                )

    def test_stack_chk_fail_call_block_must_belong_to_function(self):
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
            "4883c418"  # alternate return: add rsp, 0x18
            "c3"  # ret
        )
        project, _, function, _ = self._collect_shellcode(code, failure_name="__stack_chk_fail")
        check_node = function.startpoint
        assert isinstance(check_node, BlockNode)
        target = next(
            target
            for _, target, _ in function.transition_graph.out_edges(check_node, data=True)
            if isinstance(target, BlockNode)
        )
        fake_call = BlockNode(target.addr, target.size + 1)
        self.assertNotEqual(function.get_node(fake_call.addr), fake_call)
        function.transition_graph.add_edge(check_node, fake_call, type="transition", outside=False)
        function.transition_graph.add_edge(
            fake_call,
            FuncNode(check_node.addr + len(code)),
            type="call",
            outside=True,
        )

        facts = project.analyses.FunctionFactCollector(function)

        self.assertEqual(facts.retval_size, 8)

    def test_canary_provenance_rejects_unknown_internal_edges(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )
        project, _, function, _ = self._collect_shellcode(code, failure_name="__stack_chk_fail")
        check_node = function.startpoint
        assert isinstance(check_node, BlockNode)
        unknown_source = BlockNode(check_node.addr + 0x1000, 1)
        function.transition_graph.add_edge(unknown_source, check_node, type="unknown-internal-edge", outside=False)

        facts = project.analyses.FunctionFactCollector(function)

        self.assertEqual(facts.retval_size, 8)

    def test_canary_provenance_rejects_transitions_from_outside_function(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )
        for name in ("different_address", "same_address_different_size"):
            with self.subTest(name=name):
                project, _, function, _ = self._collect_shellcode(code, failure_name="__stack_chk_fail")
                check_node = function.startpoint
                assert isinstance(check_node, BlockNode)
                external_source = (
                    BlockNode(check_node.addr + 4, 1)
                    if name == "different_address"
                    else BlockNode(check_node.addr, check_node.size - 1)
                )
                self.assertNotEqual(function.get_node(external_source.addr), external_source)
                function.transition_graph.add_edge(external_source, check_node, type="transition", outside=False)

                facts = project.analyses.FunctionFactCollector(function)

                self.assertEqual(facts.retval_size, 8)

    def test_arithmetic_derived_canary_values_remain_return_values(self):
        tails = {
            "tls_plus_one": (
                "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
                "4883c001"  # add rax, 1
                "482b442408"  # sub rax, qword ptr [rsp + 8]
            ),
            "tls_minus_one": (
                "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
                "4883e801"  # sub rax, 1
                "482b442408"  # sub rax, qword ptr [rsp + 8]
            ),
            "saved_plus_one": (
                "488b442408"  # mov rax, qword ptr [rsp + 8]
                "4883c001"  # add rax, 1
                "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            ),
            "saved_minus_one": (
                "488b442408"  # mov rax, qword ptr [rsp + 8]
                "4883e801"  # sub rax, 1
                "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            ),
        }
        prefix = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
        )
        epilogue = bytes.fromhex(
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        for name, tail in tails.items():
            with self.subTest(name=name):
                self._assert_shellcode_return_type(
                    prefix + bytes.fromhex(tail) + epilogue,
                    8,
                    failure_name="__stack_chk_fail",
                )

    def test_stored_arithmetic_derived_tls_value_is_a_return_value(self):
        for operation in ("4883c001", "4883e801"):  # add/sub rax, 1
            with self.subTest(operation=operation):
                code = bytes.fromhex(
                    "4883ec18"  # sub rsp, 0x18
                    "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
                    + operation
                    + "4889442408"  # mov qword ptr [rsp + 8], rax
                    "488b442408"  # mov rax, qword ptr [rsp + 8]
                    "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
                    "7505"  # jne stack_chk_fail
                    "4883c418"  # add rsp, 0x18
                    "c3"  # ret
                    "e800000000"  # call stack_chk_fail
                )

                self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_dirty_helper_clobber_of_canary_register_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "0fa2"  # cpuid
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_syscall_clobber_of_canary_register_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "0f05"  # syscall
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_direct_tls_load_can_be_a_real_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b142528000000"  # mov rdx, qword ptr fs:[0x28]
            "4889542408"  # mov qword ptr [rsp + 8], rdx
            "31c0"  # xor eax, eax
            "488b542408"  # mov rdx, qword ptr [rsp + 8]
            "64482b142528000000"  # sub rdx, qword ptr fs:[0x28]
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_narrowed_canary_arithmetic_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "31c0"  # xor eax, eax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "0fb6c0"  # movzx eax, al
            "85c0"  # test eax, eax
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_partially_overwritten_saved_canary_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "40887c240c"  # mov byte ptr [rsp + 0xc], dil
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_overwritten_tls_canary_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec28"  # sub rsp, 0x28
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442418"  # mov qword ptr [rsp + 0x18], rax
            "6448893c2528000000"  # mov qword ptr fs:[0x28], rdi
            "488b442418"  # mov rax, qword ptr [rsp + 0x18]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c428"  # add rsp, 0x28
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_same_stack_expression_after_stack_adjustment_is_not_the_saved_canary(self):
        code = bytes.fromhex(
            "4883ec28"  # sub rsp, 0x28
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442418"  # mov qword ptr [rsp + 0x18], rax
            "4883c408"  # add rsp, 8
            "488b442418"  # mov rax, qword ptr [rsp + 0x18]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c420"  # add rsp, 0x20
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_atomic_overwrite_of_saved_canary_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "f0480fb17c2408"  # lock cmpxchg qword ptr [rsp + 8], rdi
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_aliased_overwrite_of_saved_canary_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "488d4c2408"  # lea rcx, [rsp + 8]
            "488939"  # mov qword ptr [rcx], rdi
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_spilled_alias_overwrite_of_saved_canary_is_a_return_value(self):
        code = bytes.fromhex(
            "4883ec28"  # sub rsp, 0x28
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442418"  # mov qword ptr [rsp + 0x18], rax
            "488d4c2418"  # lea rcx, [rsp + 0x18]
            "48894c2408"  # mov qword ptr [rsp + 8], rcx
            "31c9"  # xor ecx, ecx
            "488b4c2408"  # mov rcx, qword ptr [rsp + 8]
            "488939"  # mov qword ptr [rcx], rdi
            "488b442418"  # mov rax, qword ptr [rsp + 0x18]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c428"  # add rsp, 0x28
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_canary_saved_through_stack_alias_is_not_a_return_value(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "488d4c2408"  # lea rcx, [rsp + 8]
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "488901"  # mov qword ptr [rcx], rax
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        self._assert_shellcode_return_type(code, None, failure_name="__stack_chk_fail")

    def test_dead_canary_slot_is_not_preserved_across_a_call(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "4883c420"  # add rsp, 0x20, moving the saved slot below rsp
            "e81e000000"  # call helper
            "4883ec20"  # sub rsp, 0x20
            "488b442408"  # mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e801000000"  # call stack_chk_fail
            "c3"  # helper: ret
        )

        self._assert_shellcode_return_type(code, 8, failure_name="__stack_chk_fail")

    def test_canary_provenance_must_hold_on_every_path(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "85ff"  # test edi, edi
            "7410"  # je ordinary_value
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "eb05"  # jmp shared_epilogue
            "48897c2408"  # ordinary_value: mov qword ptr [rsp + 8], rdi
            "488b442408"  # shared_epilogue: mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        for reverse_successors in (False, True):
            with self.subTest(reverse_successors=reverse_successors):
                project, cfg, function, facts = self._collect_shellcode(
                    code,
                    failure_name="__stack_chk_fail",
                    reverse_entry_successors=reverse_successors,
                )
                cc_analysis = project.analyses.CallingConvention(
                    function,
                    cfg=cfg.model,
                    input_args=facts.input_args,
                    retval_size=facts.retval_size,
                )
                assert cc_analysis.prototype is not None
                self.assertEqual(facts.retval_size, 8)
                self.assertNotIsInstance(cc_analysis.prototype.returnty, SimTypeBottom)

    def test_canary_provenance_is_preserved_across_equivalent_paths(self):
        code = bytes.fromhex(
            "4883ec18"  # sub rsp, 0x18
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "4889442408"  # mov qword ptr [rsp + 8], rax
            "85ff"  # test edi, edi
            "7402"  # je second_path
            "eb01"  # jmp shared_epilogue
            "90"  # second_path: nop
            "488b442408"  # shared_epilogue: mov rax, qword ptr [rsp + 8]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c418"  # add rsp, 0x18
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )

        for reverse_successors in (False, True):
            with self.subTest(reverse_successors=reverse_successors):
                _, _, _, facts = self._collect_shellcode(
                    code,
                    failure_name="__stack_chk_fail",
                    reverse_entry_successors=reverse_successors,
                )
                self.assertIsNone(facts.retval_size)

    def test_path_dependent_vex_updates_are_not_propagated_to_exit_edge(self):
        code = bytes.fromhex(
            "4883ec28"  # sub rsp, 0x28
            "488d7c2418"  # lea rdi, [rsp + 0x18]
            "64488b042528000000"  # mov rax, qword ptr fs:[0x28]
            "f348ab"  # rep stosq
            "488b442418"  # mov rax, qword ptr [rsp + 0x18]
            "64482b042528000000"  # sub rax, qword ptr fs:[0x28]
            "7505"  # jne stack_chk_fail
            "4883c428"  # add rsp, 0x28
            "c3"  # ret
            "e800000000"  # call stack_chk_fail
        )
        project, _, function, _ = self._collect_shellcode(code, failure_name="__stack_chk_fail")
        loop_edge = next((source, target) for source, target in function.transition_graph.edges() if source == target)
        function.transition_graph.remove_edge(*loop_edge)

        facts = project.analyses.FunctionFactCollector(function)

        self.assertEqual(facts.retval_size, 8)

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

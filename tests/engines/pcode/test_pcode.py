#!/usr/bin/env python3
from __future__ import annotations

import os
from unittest import TestCase, main

import archinfo
from pypcode import OpCode

import angr
from angr.calling_conventions import SimCC, SimComboArg, SimRegArg, SimStackArg, default_cc
from angr.codenode import BlockNode, FuncNode
from angr.engines.pcode.cc import (
    SimCCPCodeX86Win16FarCdecl,
    SimCCPCodeX86Win16FarPascal,
    SimCCPCodeX86Win16NearCdecl,
    SimCCPCodeX86Win16NearPascal,
    register_pcode_arch_default_cc,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestPcodeEngine(TestCase):
    def test_x86_win16_near_cdecl(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            b"\xc3",
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        cc_type = default_cc(arch.name, platform="Win16")
        assert cc_type is SimCCPCodeX86Win16NearCdecl
        cc = project.factory.cc()
        assert isinstance(cc, SimCCPCodeX86Win16NearCdecl)
        assert cc.STACKARG_SP_DIFF == 2
        assert SimRegArg("ax", 2) == cc.RETURN_VAL
        assert SimStackArg(0, 2) == cc.RETURN_ADDR
        assert arch.call_pushes_ret is True
        assert arch.call_sp_fix == -2

        cfg = project.analyses.CFGFast(
            function_starts=[0],
            regions=[(0, 1)],
            start_at_entry=False,
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )
        function = cfg.functions[0]
        project.analyses.VariableRecoveryFast(function)
        analysis = project.analyses.CallingConvention(function, cfg=cfg.model)
        assert isinstance(analysis.cc, SimCCPCodeX86Win16NearCdecl)

    def test_x86_win16_far_pascal_argument_order_and_cleanup(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        cc = SimCCPCodeX86Win16FarPascal(arch)
        prototype = SimTypeFunction(
            [
                SimTypeShort(signed=False),
                SimTypeLong(signed=False),
                SimTypeChar(signed=False),
            ],
            SimTypeLong(signed=False),
        ).with_arch(arch)

        first, second, third = cc.arg_locs(prototype)
        assert first == SimStackArg(10, 2)
        assert isinstance(second, SimComboArg)
        assert second.locations == [SimStackArg(6, 2), SimStackArg(8, 2)]
        assert third == SimStackArg(4, 1)
        assert cc.stack_space([first, second, third]) == 12
        assert cc.CALLEE_CLEANUP is True
        assert SimStackArg(0, 4) == cc.RETURN_ADDR
        assert cc.return_val(prototype.returnty) == SimComboArg([SimRegArg("ax", 2), SimRegArg("dx", 2)])

    def test_x86_win16_authoritative_far_callback_renders_complete_prototype(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            bytes.fromhex("8a460c8b4604ca0a00"),  # byte use of hwnd; word use of lparam; retf 10
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        cfg = project.analyses.CFGFast(
            function_starts=[0],
            regions=[(0, 9)],
            start_at_entry=False,
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )
        function = cfg.functions[0]
        facts = project.analyses.FunctionFactCollector(function)
        assert facts.return_address_size == 4
        assert facts.return_address_size_ambiguous is False
        assert facts.extra_pop == 10

        function.calling_convention = SimCCPCodeX86Win16FarPascal(arch)
        function.prototype = SimTypeFunction(
            [
                SimTypeShort(signed=False),
                SimTypeShort(signed=False),
                SimTypeShort(signed=False),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
            arg_names=["hwnd", "message", "wparam", "lparam"],
        ).with_arch(arch)
        function.prototype_source = PrototypeSource.SIGNATURES

        decompilation = project.analyses.Decompiler(
            function,
            cfg=cfg.model,
            fail_fast=False,
            use_cache=False,
            update_cache=False,
        )

        assert decompilation.codegen is not None
        assert (
            "long _start(unsigned short hwnd, unsigned short message, unsigned short wparam, long lparam)"
            in decompilation.codegen.text
        )
        assert "|" in decompilation.codegen.text
        assert "<< 16" in decompilation.codegen.text
        assert "(unsigned long)" in decompilation.codegen.text
        assert not decompilation.codegen.unsupported_constructs
        assert [argument.size for argument in decompilation.clinic.arg_list] == [2, 2, 2, 4]
        assert [argument.offset for argument in decompilation.clinic.arg_list] == [12, 10, 8, 4]

    def test_x86_win16_near_pascal_argument_order_cleanup_and_detection(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        register_pcode_arch_default_cc(arch)
        cc = SimCCPCodeX86Win16NearPascal(arch)
        prototype = SimTypeFunction(
            [
                SimTypeShort(signed=False),
                SimTypeLong(signed=False),
                SimTypeChar(signed=False),
            ],
            SimTypeLong(signed=False),
        ).with_arch(arch)

        first, second, third = cc.arg_locs(prototype)
        assert first == SimStackArg(8, 2)
        assert isinstance(second, SimComboArg)
        assert second.locations == [SimStackArg(4, 2), SimStackArg(6, 2)]
        assert third == SimStackArg(2, 1)
        assert cc.stack_space([first, second, third]) == 10
        assert cc.CALLEE_CLEANUP is True
        assert SimStackArg(0, 2) == cc.RETURN_ADDR
        assert isinstance(
            SimCC.find_cc(
                arch,
                [SimStackArg(2, 2), SimStackArg(4, 2)],
                2,
                platform="Win16",
                extra_pop=4,
            ),
            SimCCPCodeX86Win16NearPascal,
        )

    def test_x86_win16_combo_argument_is_one_c_argument(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        code = bytes.fromhex("6811116844336866556a77e81200c3") + b"\x90" * (0x20 - 15) + bytes.fromhex("c20800")
        project = angr.load_shellcode(
            code,
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        project.simos.name = "Win16"
        cfg = project.analyses.CFGFast(
            function_starts=[0, 0x20],
            regions=[(0, len(code))],
            start_at_entry=False,
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )
        callee = cfg.functions[0x20]
        callee.calling_convention = SimCCPCodeX86Win16NearPascal(arch)
        callee.prototype = SimTypeFunction(
            [SimTypeShort(signed=False), SimTypeLong(signed=False), SimTypeChar(signed=False)],
            SimTypeBottom(label="void"),
        ).with_arch(arch)
        callee.prototype_source = PrototypeSource.SIGNATURES

        caller = cfg.functions[0]
        caller.calling_convention = SimCCPCodeX86Win16NearPascal(arch)
        caller.prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)
        caller.prototype_source = PrototypeSource.SIGNATURES
        decompilation = project.analyses.Decompiler(
            caller,
            cfg=cfg.model,
            fail_fast=True,
            use_cache=False,
            update_cache=False,
        )

        assert decompilation.codegen is not None
        call_line = next(line for line in decompilation.codegen.text.splitlines() if "sub_20(" in line)
        assert call_line.count(",") == 2
        assert " | " in call_line
        assert "<< 16" in call_line
        assert "(unsigned long)" in call_line

    def test_x86_win16_pcode_facts_recover_stack_arguments_and_return_width(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            bytes.fromhex("5589e58b46040346065dc20400"),
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        project.simos.name = "Win16"
        cfg = project.analyses.CFGFast(
            function_starts=[0],
            regions=[(0, 13)],
            start_at_entry=False,
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )
        function = cfg.functions[0]

        facts = project.analyses.FunctionFactCollector(function)
        assert facts.input_args == [SimStackArg(2, 2), SimStackArg(4, 2)]
        assert facts.retval_size == 2
        assert facts.return_address_size == 2
        assert facts.return_address_size_ambiguous is False
        assert facts.extra_pop == 4

        analysis = project.analyses.CallingConvention(
            function,
            cfg=cfg.model,
            collect_facts=True,
        )
        assert isinstance(analysis.cc, SimCCPCodeX86Win16NearPascal)
        assert analysis.prototype is not None
        assert len(analysis.prototype.args) == 2

    def test_x86_win16_pcode_facts_ignore_zero_idiom_inputs_but_keep_register_helpers(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")

        def facts(machine_code: bytes):
            project = angr.load_shellcode(
                machine_code,
                arch=arch,
                load_address=0,
                engine=angr.engines.UberEnginePcode,
                rebase_granularity=0x10,
            )
            project.simos.name = "Win16"
            cfg = project.analyses.CFGFast(
                function_starts=[0],
                regions=[(0, len(machine_code))],
                start_at_entry=False,
                force_complete_scan=False,
                force_smart_scan=False,
                normalize=True,
                resolve_indirect_jumps=False,
            )
            return project.analyses.FunctionFactCollector(cfg.functions[0])

        # Both paths zero CX before use. The branch makes this a regression for
        # per-instruction p-code flag operations, not merely a straight-line
        # write-before-read case. Only [BP+4] is an ABI argument.
        conventional = facts(bytes.fromhex("5589e58b5e0483fb00740633c98bc1eb0233c05dc3"))
        assert conventional.input_args == [SimStackArg(2, 2)]

        # A true register-entry helper must remain unclassifiable as the
        # stack-only Win16 C ABI instead of silently losing its AX input.
        register_helper = facts(bytes.fromhex("050100c3"))  # add ax, 1; ret
        assert register_helper.input_args == [SimRegArg("ax", 2)]

        # Segment, flags, x87 control state, and ST0 are ambient machine state,
        # not C arguments. The only ABI input in this machine-code fixture is
        # the word at [BP+4].
        ambient_code = bytes.fromhex("5589e583ec021e9cd97efed9c0ddd8d96efe9d1f8b460489ec5dc3")
        project = angr.load_shellcode(
            ambient_code,
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        project.simos.name = "Win16"
        cfg = project.analyses.CFGFast(
            function_starts=[0],
            regions=[(0, len(ambient_code))],
            start_at_entry=False,
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )
        ambient_facts = project.analyses.FunctionFactCollector(cfg.functions[0])
        assert ambient_facts.input_args == [SimStackArg(2, 2)]
        ambient_cc = project.analyses.CallingConvention(cfg.functions[0], cfg=cfg.model, collect_facts=True)
        assert isinstance(ambient_cc.cc, SimCCPCodeX86Win16NearCdecl)
        assert ambient_cc.prototype is not None
        assert len(ambient_cc.prototype.args) == 1

    def test_x86_win16_swi_clobbers_caller_saved_registers_without_shifting_the_stack(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        register_pcode_arch_default_cc(arch)
        # push bp; mov bp,sp; mov ah,2ah; int 21h; mov bx,dx;
        # mov si,cx; mov ax,[bp+4]; pop bp; ret
        code = bytes.fromhex("5589e5b42acd2189d389ce8b46045dc3")
        project = angr.load_shellcode(
            code,
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        project.simos.name = "Win16"
        cfg = project.analyses.CFGFast(
            function_starts=[0],
            regions=[(0, len(code))],
            start_at_entry=False,
            force_complete_scan=False,
            force_smart_scan=False,
            normalize=True,
            resolve_indirect_jumps=False,
        )

        # Shellcode has no Win16 interrupt-vector environment, so CFGFast cannot
        # resolve SLEIGH's synthetic SWI CALLIND. Add exactly the call/fake-return
        # shape a resolved binary supplies; all instruction semantics remain the
        # raw bytes above.
        function = cfg.functions[0]
        assert function.startpoint is not None
        swi_target = project.kb.functions.function(addr=0x100, create=True)
        assert swi_target is not None
        swi_target.returning = True
        continuation = BlockNode(7, len(code) - 7)
        function._call_to(  # pylint:disable=protected-access
            function.startpoint,
            FuncNode(0x100),
            continuation,
            ins_addr=5,
        )
        function._add_return_site(continuation)  # pylint:disable=protected-access

        facts = project.analyses.FunctionFactCollector(function)
        assert facts.input_args == [SimStackArg(2, 2)]
        assert facts.return_address_size == 2
        assert facts.extra_pop == 0

        analysis = project.analyses.CallingConvention(function, cfg=cfg.model, collect_facts=True)
        assert isinstance(analysis.cc, SimCCPCodeX86Win16NearCdecl)
        assert analysis.prototype is not None
        assert len(analysis.prototype.args) == 1

    def test_x86_win16_pcode_facts_distinguish_far_cdecl_and_pascal(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        cases = (
            ("5589e58b46065dcb", SimCCPCodeX86Win16FarCdecl, 0),
            ("5589e58b46065dca0200", SimCCPCodeX86Win16FarPascal, 2),
        )
        for code, expected_cc, expected_extra_pop in cases:
            project = angr.load_shellcode(
                bytes.fromhex(code),
                arch=arch,
                load_address=0,
                engine=angr.engines.UberEnginePcode,
                rebase_granularity=0x10,
            )
            project.simos.name = "Win16"
            cfg = project.analyses.CFGFast(
                function_starts=[0],
                regions=[(0, len(bytes.fromhex(code)))],
                start_at_entry=False,
                force_complete_scan=False,
                force_smart_scan=False,
                normalize=True,
                resolve_indirect_jumps=False,
            )
            function = cfg.functions[0]
            facts = project.analyses.FunctionFactCollector(function)
            assert facts.input_args == [SimStackArg(4, 2)]
            assert facts.return_address_size == 4
            assert facts.extra_pop == expected_extra_pop

            analysis = project.analyses.CallingConvention(
                function,
                cfg=cfg.model,
                collect_facts=True,
            )
            assert isinstance(analysis.cc, expected_cc)
            assert analysis.prototype is not None
            assert len(analysis.prototype.args) == 1

    def test_x86_win16_block_stack_tracking_tolerates_call(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            bytes.fromhex("e80000"),  # call the following instruction
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        block = project.factory.block(0, num_inst=1)

        tracker = project.analyses.StackPointerTracker(
            None,
            {arch.sp_offset},
            block=block,
            track_memory=False,
        )

        assert tracker.offset_after(0, arch.sp_offset) is not None

    def test_x86_real_mode_segment_userop(self):
        arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
        project = angr.load_shellcode(
            bytes.fromhex("a10010"),  # mov ax, word ptr ds:[0x1000]
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        irsb = project.factory.block(0, size=3).vex
        segment_op = next(op for op in irsb._ops if op.opcode == OpCode.CALLOTHER)
        assert segment_op.inputs[0].getUserDefinedOpName() == "segment"

        state = project.factory.blank_state(addr=0)
        state.regs.ds = 0xFFFF
        state.memory.store(0x0FF0, b"\x34\x12")
        state.memory.store(0x100FF0, b"\x78\x56")

        successors = project.factory.successors(state, num_inst=1)

        assert len(successors.successors) == 1
        successor = successors.successors[0]
        assert successor.solver.eval(successor.regs.ax) == 0x1234
        assert successor.solver.eval(successor.regs.pc) == 3

    def test_x86_protected_mode_segment_userop(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            bytes.fromhex("a10010"),  # mov ax, word ptr ds:[0x1000]
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        irsb = project.factory.block(0, size=3).vex
        segment_op = next(op for op in irsb._ops if op.opcode == OpCode.CALLOTHER)
        assert segment_op.inputs[0].getUserDefinedOpName() == "segment"

        state = project.factory.blank_state(addr=0)
        state.regs.ds = 3
        state.memory.store(0x31000, b"\x34\x12")

        successors = project.factory.successors(state, num_inst=1)

        assert len(successors.successors) == 1
        successor = successors.successors[0]
        assert successor.solver.eval(successor.regs.ax) == 0x1234
        assert successor.solver.eval(successor.regs.pc) == 3

    def test_x86_protected_mode_lock_markers_execute_sequential_update(self):
        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            bytes.fromhex("f0ff07"),  # lock inc word ptr [bx]
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        state = project.factory.blank_state(addr=0)
        state.regs.ds = 3
        state.regs.bx = 0x1000
        state.memory.store(0x31000, b"\x34\x12")

        successors = project.factory.successors(state, num_inst=1)

        assert len(successors.successors) == 1
        successor = successors.successors[0]
        value = successor.memory.load(0x31000, 2, endness=arch.memory_endness)
        assert successor.solver.eval(value) == 0x1235
        assert successor.solver.eval(successor.regs.pc) == 3

    def test_cfg_preserves_return_path_after_unresolved_far_jump(self):
        code = bytearray(b"\x90" * 0x50)
        code[0:3] = bytes.fromhex("e80d00")  # call 0x10
        code[3:8] = bytes.fromhex("9a40000000")  # callf 0000:0040
        code[8] = 0xC3
        code[0x10:0x14] = bytes.fromhex("ff2e3000")  # jmpf [0030]
        code[0x30:0x34] = bytes.fromhex("03000000")
        code[0x40] = 0xC3

        arch = archinfo.ArchPcode("x86:LE:16:Protected Mode")
        project = angr.load_shellcode(
            bytes(code),
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )
        cfg = project.analyses.CFGFast(
            resolve_indirect_jumps=False,
            force_smart_scan=False,
            force_complete_scan=False,
            function_prologues=False,
            symbols=False,
            data_references=False,
        )

        assert 0x10 in cfg.kb.unresolved_indirect_jumps
        assert cfg.kb.functions[0x10].returning is None
        call_node = cfg.model.get_any_node(0)
        continuation_node = cfg.model.get_any_node(3)
        assert continuation_node is not None
        assert cfg.graph.get_edge_data(call_node, continuation_node)["jumpkind"] == "Ijk_FakeRet"
        assert cfg.model.get_any_node(0x40) is not None
        assert cfg.kb.functions[0].returning is True

    def test_x86_real_mode_unknown_userop_fails_closed(self):
        arch = archinfo.ArchPcode("x86:LE:16:Real Mode")
        project = angr.load_shellcode(
            bytes.fromhex("cd21"),  # int 0x21
            arch=arch,
            load_address=0,
            engine=angr.engines.UberEnginePcode,
            rebase_granularity=0x10,
        )

        state = project.factory.blank_state(addr=0)
        with self.assertRaisesRegex(angr.errors.AngrError, "swi"):
            project.factory.successors(state, num_inst=1)

    def test_shellcode(self):
        """
        Test basic CFG recovery and symbolic/concrete execution paths.
        """
        base_address = 0
        prototype = "int node_d(long)"
        code = archinfo.arch_from_id("AMD64").asm(
            """
        node_a:
            test rdi, rdi
            jz node_c
        node_b:
            mov rax, 0x1234
            jmp node_d
        node_c:
            mov rax, 0x5678
        node_d:
            ret
        """,
            base_address,
        )

        arch = archinfo.ArchPcode("x86:LE:64:default")
        angr.calling_conventions.register_default_cc(arch.name, angr.calling_conventions.SimCCSystemVAMD64)
        p = angr.load_shellcode(code, arch=arch, load_address=base_address, engine=angr.engines.UberEnginePcode)

        # Recover the CFG
        c = p.analyses.CFGFast(normalize=True)
        assert len(list(c.model.nodes())) == 4

        # Execute symbolically
        s = p.factory.call_state(base_address, prototype=prototype)
        simgr = p.factory.simulation_manager(s)
        simgr.run()
        assert sum(len(i) for i in simgr.stashes.values()) == 2
        assert {s.solver.eval(s.regs.rax) for s in simgr.deadended} == {0x1234, 0x5678}

        # Execute concretely
        callable_func = p.factory.callable(base_address, prototype=prototype, concrete_only=True)
        for input_, expected_output in [(0, 0x5678), (1, 0x1234), (0xFFFFFFFFFFFFFFFF, 0x1234)]:
            assert (callable_func(input_) == expected_output).is_true()

    def test_fauxware(self):
        """
        Test basic fauxware execution.
        """
        p = angr.Project(
            os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False, engine=angr.engines.UberEnginePcode
        )
        simgr = p.factory.simgr()
        simgr.run()

        assert sum(len(i) for i in simgr.stashes.values()) == len(simgr.deadended) == 3

        grant_paths = [s for s in simgr.deadended if b"trusted" in s.posix.dumps(1)]
        assert len(grant_paths) == 2
        assert sum(s.posix.dumps(0) == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00" for s in grant_paths) == 1

        deny_paths = [s for s in simgr.deadended if b"Go away!" in s.posix.dumps(1)]
        assert len(deny_paths) == 1

    def test_riscv64_int_right_behavior(self):
        """
        Test the use of correct bitvector extension in behavior INT_RIGHT
        """
        #     beq x12, x0, 12 ; srliw x31, x5, 31
        byte_code = 0x00060663_01F2DF9B.to_bytes(8, "little")
        # abi names: t0 = x5, t6 = x31

        arch = archinfo.ArchPcode("RISCV:LE:64:default")
        p = angr.load_shellcode(byte_code, arch=arch, load_address=0, engine=angr.engines.UberEnginePcode)

        entry_state = p.factory.entry_state()
        entry_state.registers.store("t0", 2**32 - 1)  # bits 31..0 are set

        simgr = p.factory.simulation_manager(entry_state)
        simgr = simgr.step()

        # |-32bit-|
        # 111...111 >>(logical) 31 = 1

        assert simgr.active[0].regs.t6.concrete
        assert simgr.active[0].regs.t6.concrete_value == 1

    def test_callless_function_graph_consistency(self):
        binary_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(
            binary_path,
            load_options={"auto_load_libs": False},
            engine=angr.engines.UberEnginePcode,
        )

        # Address 400550: ff 25 ca 0a 20 00 jmp *0x200aca(%rip) # 601020 <strcmp@GLIBC_2.2.5>
        # This is a PLT stub. Current limitations in the P-Code engine cause it to
        # misidentify this indirect jump as 'Ijk_Boring', leading to a disconnected
        # function graph that creates a false negative in this test.
        #
        # Since the purpose of this test is specifically to verify the CALLLESS logic
        # and not P-Code's jumpkind resolution, we manually hook this address with
        # a SimProcedure. This bypasses the engine's parsing limitations and ensures
        # the CALLLESS mechanism can correctly generate the expected FakeRet edge.
        proj.hook(0x400550, angr.SimProcedure(return_value=0), length=6)

        cfg = proj.analyses.CFGEmulated(
            keep_state=True,
            fail_fast=True,
            starts=[0x400664],  # authenticate
            state_add_options={angr.options.CALLLESS},
        )

        # For each node in cfg.graph that has outgoing edges,
        # verify that the corresponding node in function.graph also has outgoing edges.
        # A node with successors in cfg.graph but none in function.graph indicates
        # the bug where CALLLESS converts Ijk_Call to Ijk_Ret, causing
        # _update_function_transition_graph to invoke _add_return_from instead of
        # _add_fakeret_to, leaving call blocks disconnected in function.graph.
        for cfg_node in cfg.graph.nodes():
            cfg_out = cfg.graph.out_degree(cfg_node)
            if cfg_out == 0:
                continue
            # look up the function this node belongs to
            func = cfg.kb.functions.get_by_addr(cfg_node.function_address)
            if func is None:
                continue
            # find the corresponding node in function.graph
            func_node = next((n for n in func.graph.nodes() if n.addr == cfg_node.addr), None)
            if func_node is None:
                continue
            func_out = func.graph.out_degree(func_node)
            assert func_out > 0


if __name__ == "__main__":
    main()

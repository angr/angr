#!/usr/bin/env python3
from __future__ import annotations

import os
import pickle
import threading
from unittest import TestCase, main

import archinfo
import pyvex

import angr
from angr.engines.pcode import lifter as pcode_lifter

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
# pylint: disable=protected-access
class TestPcodeEngine(TestCase):
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

    def test_sleigh_context_is_not_shared_between_projects(self):
        """
        Test that a project's blocks do not depend on which other projects were lifted before it.

        Sleigh records context variables per address, so a PA-RISC branch lifted in one project used to leave the
        delay slot context it sets behind at the following address, and an unrelated project's instruction at that
        address was then decoded as that branch's delay slot.
        """
        base_addr = 0x1000
        nop = b"\x08\x00\x02\x40"  # or %r0, %r0, %r0
        branch = b"\xe8\x00\x00\x10"  # b 0x1010, whose delay slot is the instruction at 0x1004
        arch = archinfo.ArchPcode("pa-risc:BE:32:default")

        def project(code):
            return angr.load_shellcode(code, arch=arch, load_address=base_addr, engine=angr.engines.UberEnginePcode)

        def delay_slot_block():
            block = project(nop * 8).factory.block(base_addr + 4)
            next_expr = block.vex.next
            assert isinstance(next_expr, pyvex.expr.Const)
            return block.size, block.vex.jumpkind, next_expr.con.value

        before = delay_slot_block()
        assert before == (28, "Ijk_Boring", 0x1020)

        # Lift the branch in another project, writing its delay slot context at base_addr + 4. The branch and its
        # delay slot are one two-instruction block, which is what leaves the context behind.
        branch_block = project(branch + nop * 7).factory.block(base_addr)
        assert (branch_block.size, branch_block.instructions) == (8, 2)

        assert delay_slot_block() == before

    def test_block_lifter_is_kept_per_project(self):
        """
        Test that a project decodes with one basic block lifter, and therefore one Sleigh context.

        Block.pcode reads that context, so a project whose engine is not the p-code engine must neither share one
        with another project nor build one for every block.
        """
        code = b"\x13\x00\x00\x00" * 4  # four RISC-V nops
        first = angr.load_shellcode(code, arch="RISCV64", load_address=0)
        second = angr.load_shellcode(code, arch="RISCV64", load_address=0)

        assert [insn.mnemonic for insn in first.factory.block(0).pcode.insns] == ["nop"] * 4

        block_lifter = pcode_lifter.get_block_lifter(first, first.arch)
        assert pcode_lifter.get_block_lifter(first, first.arch) is block_lifter
        assert pcode_lifter.get_block_lifter(second, second.arch) is not block_lifter

        # a lifter decodes one architecture, so asking for another replaces it rather than decoding with it
        other_arch = archinfo.ArchPcode("pa-risc:BE:32:default")
        assert pcode_lifter.get_block_lifter(first, other_arch).arch == other_arch
        assert pcode_lifter.get_block_lifter(first, first.arch) is not block_lifter

        # a Sleigh context cannot be pickled, so the lifter a project keeps must not go into its pickle
        restored = pickle.loads(pickle.dumps(first))
        assert [insn.mnemonic for insn in restored.factory.block(0).pcode.insns] == ["nop"] * 4

        # a project running the p-code engine keeps it in the same place, so its engine and its Block.pcode decode
        # with one context rather than one each
        arch = archinfo.ArchPcode("pa-risc:BE:32:default")
        third = angr.load_shellcode(
            b"\x08\x00\x02\x40" * 4, arch=arch, load_address=0x1000, engine=angr.engines.UberEnginePcode
        )
        assert third._pcode_block_lifter is None
        assert third.factory.block(0x1000).instructions == 4
        assert third._pcode_block_lifter is not None
        assert pcode_lifter.get_block_lifter(third, arch) is third._pcode_block_lifter

    def test_block_lifter_is_shared_between_threads(self):
        """
        Test that a project decodes with one basic block lifter whichever thread lifts.

        The factory hands out one engine per thread, so keeping the lifter on the engine gave each thread its own
        Sleigh context and made a block's decoding depend on which thread reached it first.
        """
        arch = archinfo.ArchPcode("pa-risc:BE:32:default")
        proj = angr.load_shellcode(
            b"\x08\x00\x02\x40" * 4, arch=arch, load_address=0x1000, engine=angr.engines.UberEnginePcode
        )
        assert proj.factory.block(0x1000).instructions == 4
        main_lifter = proj._pcode_block_lifter
        assert main_lifter is not None

        seen = []

        def lift_in_thread():
            proj.factory.block(0x1000)
            seen.append((proj.factory.default_engine, pcode_lifter.get_block_lifter(proj, arch)))

        thread = threading.Thread(target=lift_in_thread)
        thread.start()
        thread.join()

        assert len(seen) == 1
        other_engine, other_lifter = seen[0]
        assert other_engine is not proj.factory.default_engine  # the factory really did hand out a second engine
        assert other_lifter is main_lifter


if __name__ == "__main__":
    main()

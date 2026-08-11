#!/usr/bin/env python3
from __future__ import annotations

import os
from unittest import TestCase, main

import archinfo

import angr
from angr.engines.pcode.lifter import IRSB_MAX_SIZE

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
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

    def test_block_stops_at_the_last_fully_mapped_instruction(self):
        """
        Test that a block does not run past the end of the image.
        """
        # 0xe8 opens a five-byte "call rel32", so the last byte of this image starts an instruction whose
        # remaining four bytes are not mapped at all. Sleigh reads ahead at every instruction boundary and
        # pypcode zero-fills whatever part of that read the buffer cannot satisfy, so the call decodes from
        # bytes that are not in memory.
        code = b"\x90\x90\xe8"
        base_address = 0x400000

        arch = archinfo.ArchPcode("x86:LE:64:default")
        p = angr.load_shellcode(code, arch=arch, load_address=base_address, engine=angr.engines.UberEnginePcode)
        assert p.loader.main_object.max_addr == base_address + len(code) - 1

        block = p.factory.block(base_address)
        assert block.size == 2
        assert block.bytes == b"\x90\x90"
        assert list(block.instruction_addrs) == [base_address, base_address + 1]
        assert [insn.mnemonic for insn in block.disassembly.insns] == ["NOP", "NOP"]

        # There are not enough bytes for the instruction the block stopped in front of, so no block starts
        # there either.
        truncated = p.factory.block(base_address + 2)
        assert truncated.size == 0
        assert truncated.vex.jumpkind == "Ijk_NoDecode"

    def test_block_stops_in_front_of_an_instruction_spanning_the_byte_cap(self):
        """
        Test that a block ends before an instruction that runs past the lifter's byte cap.
        """
        # The same zero-fill applies to a fully mapped image, because the lifter hands Sleigh at most
        # IRSB_MAX_SIZE bytes at a time. This "call rel32" starts two bytes before that cap, so three of its
        # five bytes are outside the buffer and decoding it there yields the wrong target.
        call = b"\xe8\x11\x22\x33\x44"
        base_address = 0x400000
        arch = archinfo.ArchPcode("x86:LE:64:default")

        p = angr.load_shellcode(
            b"\x90" * (IRSB_MAX_SIZE - 2) + call + b"\xc3" * 16,
            arch=arch,
            load_address=base_address,
            engine=angr.engines.UberEnginePcode,
        )
        block = p.factory.block(base_address)
        assert block.size == IRSB_MAX_SIZE - 2
        assert block.vex.jumpkind == "Ijk_Boring"

        call_address = base_address + block.size
        call_block = p.factory.block(call_address)
        assert call_block.size == len(call)
        assert call_block.vex.jumpkind == "Ijk_Call"
        assert call_block.vex.next.con.value == call_address + len(call) + 0x44332211

        # An instruction that ends exactly on the cap is still one the lifter was given.
        aligned = angr.load_shellcode(
            b"\x90" * IRSB_MAX_SIZE + b"\xc3" * 16,
            arch=arch,
            load_address=base_address,
            engine=angr.engines.UberEnginePcode,
        )
        assert aligned.factory.block(base_address).size == IRSB_MAX_SIZE

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

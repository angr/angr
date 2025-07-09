"""
test_icicle.py - Unit tests for the Icicle engine in angr.

These tests are broken into two classes: TestIcicle and TestFauxware. TestIcicle
contains unit tests for basic functionality of the engine. TestFauxware contains
integration tests for running the fauxware binary using the engine.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import os
from io import BytesIO
from unittest import TestCase

import archinfo
import cle

import angr
from angr import sim_options as o
from angr.emulator import EmulatorStopReason
from angr.engines.icicle import IcicleEngine, UberIcicleEngine
from tests.common import bin_location


class TestIcicle(TestCase):
    """Unit tests for the Icicle engine."""

    def test_simple_add(self):
        """Test a simple addition operation in aarch64 shellcode."""

        # Shellcode to add 1 and 2 in aarch64
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        successors = engine.process(init_state, num_inst=3)
        assert len(successors.successors) == 1
        assert successors[0].regs.x2.concrete_value == 0x3

    def test_segfault(self):
        """Test a segmentation fault in aarch64 shellcode."""

        # Shellcode to write the value 0x42 to address 0x100000 in aarch64
        shellcode = "ldr x0, [x1]"
        project = angr.load_shellcode(shellcode, "aarch64", start_offset=0x1000, load_address=0x1000)

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # Map the region 0x0 to 0x1000 with no permissions
        init_state.memory.map_region(0x0, 0x1000, 0b000)

        # Now run the shellcode, it should segfault on the 3rd instruction
        successors = engine.process(init_state)

        # There should be no normal sucessors, but one error successor
        assert len(successors.successors) == 1

        # Check that the error occured at the expected instruction
        assert successors.successors[0].ip.concrete_value == 0x1000

    def test_hook(self):
        """Test a hook in aarch64 shellcode."""

        # Shellcode to add 1 and 2 in aarch64
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1"
        project = angr.load_shellcode(shellcode, "aarch64")

        # Hook the second instruction to set x1 to 0x42 instead of 0x2
        @project.hook(0x4, length=4)
        def hook_func(state):
            state.regs.x1 = 0x42

        engine = UberIcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # First instruction, should return after only one instruction due to the hook
        successors_1 = engine.process(init_state)
        assert len(successors_1.successors) == 1
        assert successors_1[0].regs.pc.concrete_value == 0x4
        # Run the hook
        successors_2 = engine.process(successors_1[0])
        assert len(successors_2.successors) == 1
        assert successors_2[0].regs.pc.concrete_value == 0x8
        # Run the third instruction
        successors_3 = engine.process(successors_2[0], num_inst=1)
        assert len(successors_3.successors) == 1
        assert successors_3[0].regs.pc.concrete_value == 0xC

        # Check that the value of x2 is 0x43, since x1 was set to 0x42 by the hook
        assert successors_3[0].regs.x2.concrete_value == 0x43

    def test_hook_memory(self):
        """Test a hook in aarch64 shellcode that modifies memory."""

        # Shellcode to add 1 and 2 in aarch64
        shellcode = """
        mov x0, 0x1000;
        mov x1, 0x1008;
        mov x2, 0x1;
        mov x3, 0x2;

        // Store values
        str x2, [x0];
        str x3, [x1];

        // A gap for our hook
        nop;

        // Load values
        ldr x4, [x0];
        ldr x5, [x1];

        // Add values
        add x6, x4, x5;
        """
        project = angr.load_shellcode(shellcode, "aarch64")

        # Hook the nop to change 0x1000 to 0x1234
        @project.hook(0x18, length=4)
        def hook_func(state):
            state.memory.store(0x1008, 0x42, size=8, endness="Iend_LE")

        engine = UberIcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        init_state.memory.map_region(0x1000, 0x1000, 0b111)

        # Execute up to the hook
        successors_1 = engine.process(init_state)
        assert len(successors_1.successors) == 1
        assert successors_1[0].regs.pc.concrete_value == 0x18
        # Run the hook
        successors_2 = engine.process(successors_1[0])
        assert len(successors_2.successors) == 1
        assert successors_2[0].regs.pc.concrete_value == 0x1C
        # Run the remaining instructions
        successors_3 = engine.process(successors_2[0], num_inst=3)
        assert len(successors_3.successors) == 1
        assert successors_3[0].regs.pc.concrete_value == 0x28

        # Check that the value of x6 is 0x43, since x1 was set to 0x42 by the hook
        assert successors_3[0].regs.x6.concrete_value == 0x43

    def test_syscall(self):
        """Test a syscall in aarch64 shellcode."""

        # Shellcode to invoke a syscall (exit) in aarch64
        shellcode = "svc 0"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # Now run the shellcode, it should exit normally
        successors = engine.process(init_state)

        # There should be one successor
        assert len(successors.successors) == 1
        # Check that the emulator exited at the expected instruction
        assert successors.successors[0].ip.concrete_value == 0x0
        # Check that the syscall was invoked
        assert successors.successors[0].history.jumpkind == "Ijk_Syscall"


class TestThumb(TestCase):
    """Thumb-specific tests for the Icicle engine."""

    def test_thumb(self):
        """Test that the Icicle engine can handle Thumb instructions."""

        # Shellcode to add 1 and 2 in Thumb mode
        shellcode = "mov r0, 0x1; mov r1, 0x2; add r2, r0, r1;"
        project = angr.load_shellcode(shellcode, "armel", thumb=True)

        engine = IcicleEngine(project)
        init_state = project.factory.entry_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        assert init_state.addr == 0x1

        successors = engine.process(init_state, num_inst=3)
        assert len(successors.successors) == 1
        assert successors[0].regs.pc.concrete_value == 0xD
        assert successors[0].regs.r2.concrete_value == 0x3

    def test_thumb_switching(self):
        """Test that the Icicle engine can handle switching between ARM and Thumb instructions."""

        arch = archinfo.ArchARM()

        # Set r0 and r1 to 1 and 2, then switch to thumb mode and add them
        arm_shellcode: bytes = arch.asm("mov r0, 0x1; mov r1, 0x2; mov r3, 0x1001; bx r3;")
        thumb_shellcode: bytes = arch.asm("add r2, r0, r1;", thumb=True)

        blob = cle.Blob(
            None,
            BytesIO(arm_shellcode + thumb_shellcode),
            arch=arch,
            segments=[
                (0x0, 0x0, len(arm_shellcode)),
                (len(arm_shellcode), 0x1000, len(thumb_shellcode)),
            ],
            base_addr=0x0,
            entry_point=0x0,
        )
        project = angr.Project(blob)

        engine = IcicleEngine(project)
        init_state = project.factory.entry_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        assert init_state.addr == 0x0

        successors = engine.process(init_state, num_inst=5)
        assert len(successors.successors) == 1
        assert successors[0].regs.pc.concrete_value == 0x1005
        assert successors[0].regs.r2.concrete_value == 0x3

    def test_thumb_switching_back(self):
        """Test that the Icicle engine can handle switching back from Thumb to ARM instructions."""

        arch = archinfo.ArchARM()

        # Set r0 and r1 to 1 and 2, then switch to thumb mode and add them
        thumb_shellcode: bytes = arch.asm("mov r0, 0x1; mov r1, 0x2; mov r3, 0x1000; bx r3;", thumb=True)
        arm_shellcode: bytes = arch.asm("add r2, r0, r1;", thumb=False)

        blob = cle.Blob(
            None,
            BytesIO(thumb_shellcode + arm_shellcode),
            arch=arch,
            segments=[
                (0x0, 0x0, len(thumb_shellcode)),
                (len(thumb_shellcode), 0x1000, len(arm_shellcode)),
            ],
            base_addr=0x0,
            entry_point=0x1,
        )
        project = angr.Project(blob)

        engine = IcicleEngine(project)
        init_state = project.factory.entry_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        assert init_state.addr == 0x1

        successors = engine.process(init_state, num_inst=5)
        assert len(successors.successors) == 1
        assert successors[0].history.jumpkind != "Ijk_SigSEGV"
        assert successors[0].regs.pc.concrete_value == 0x1004
        assert successors[0].regs.r2.concrete_value == 0x3


class TestFauxware(TestCase):
    """Integration tests executing the fauxware binary using the Icicle engine."""

    def _run_fauxware(self, arch):
        project = angr.Project(os.path.join(bin_location, "tests", arch, "fauxware"), auto_load_libs=False)
        init_state = project.factory.entry_state(
            stdin=b"username\nSOSNEAKY\n",
            args=["fauxware"],
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        engine = UberIcicleEngine(project)

        state = init_state.copy()
        while state.history.jumpkind != "Ijk_Exit":
            # Run the engine until we hit a syscall
            successors = engine.process(state)
            assert len(successors.successors) == 1
            assert successors.successors[0].history.jumpkind != "Ijk_SigSEGV"
            state = successors.successors[0]

        # Check that the program has printed the expected output
        assert b"Welcome to the admin console, trusted user!\n" in state.posix.dumps(1)

    def test_fauxware_i386(self):
        self._run_fauxware("i386")

    def test_fauxware_x86_64(self):
        self._run_fauxware("x86_64")

    def test_fauxware_armel(self):
        self._run_fauxware("armel")

    def test_fauxware_armhf(self):
        self._run_fauxware("armhf")

    def test_fauxware_mips(self):
        self._run_fauxware("mips")

    def test_fauxware_mipsel(self):
        self._run_fauxware("mipsel")


class TestBreakpoints(TestCase):
    """Unit tests for breakpoint functionality in the Icicle engine."""

    def test_add_breakpoint(self):
        """Test adding and hitting a breakpoint."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1; mov x3, 0x3"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # Add breakpoint at the third instruction (add x2, x0, x1)
        breakpoint_addr = project.entry + 8
        engine.add_breakpoint(breakpoint_addr)

        # Process up to the breakpoint
        successors = engine.process(init_state)
        assert len(successors.successors) == 1
        state_after_bp = successors.successors[0]
        assert state_after_bp.addr == breakpoint_addr
        assert state_after_bp.regs.x0.concrete_value == 1
        assert state_after_bp.regs.x1.concrete_value == 2

        # Continue execution
        successors2 = engine.process(state_after_bp)
        assert len(successors2.successors) == 1
        final_state = successors2.successors[0]
        assert final_state.regs.x2.concrete_value == 3
        assert final_state.regs.x3.concrete_value == 3

    def test_remove_breakpoint(self):
        """Test removing a breakpoint."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1; mov x3, 0x3"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        breakpoint_addr = project.entry + 8  # add x2, x0, x1
        engine.add_breakpoint(breakpoint_addr)
        engine.remove_breakpoint(breakpoint_addr)

        # Process all instructions, breakpoint should not be hit
        successors = engine.process(init_state, num_inst=4)
        assert len(successors.successors) == 1
        final_state = successors.successors[0]
        assert final_state.regs.x2.concrete_value == 3
        assert final_state.regs.x3.concrete_value == 3
        assert final_state.addr == project.entry + 16  # After last instruction

    def test_multiple_breakpoints(self):
        """Test multiple breakpoints."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1; mov x3, 0x3; sub x4, x3, x0"  # 5 instructions
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        bp1_addr = project.entry + 4  # mov x1, 0x2
        bp2_addr = project.entry + 12  # mov x3, 0x3
        engine.add_breakpoint(bp1_addr)
        engine.add_breakpoint(bp2_addr)

        # Process to first breakpoint
        succ1 = engine.process(init_state)
        assert len(succ1.successors) == 1
        state1 = succ1.successors[0]
        assert state1.addr == bp1_addr
        assert state1.regs.x0.concrete_value == 1

        # Process to second breakpoint
        succ2 = engine.process(state1)
        assert len(succ2.successors) == 1
        state2 = succ2.successors[0]
        assert state2.addr == bp2_addr
        assert state2.regs.x1.concrete_value == 2
        assert state2.regs.x2.concrete_value == 3

        # Process to end
        succ3 = engine.process(state2)
        assert len(succ3.successors) == 1
        state3 = succ3.successors[0]
        assert state3.regs.x3.concrete_value == 3
        assert state3.regs.x4.concrete_value == 2  # 3 - 1
        assert state3.addr == project.entry + 20  # After last instruction

    def test_breakpoint_at_start(self):
        """Test that a breakpoint at the very first instruction is ignored (execution resumes immediately)."""
        shellcode = "mov x0, 0x1; mov x1, 0x2"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        engine.add_breakpoint(project.entry)

        # The breakpoint at the entry should be ignored, so execution should proceed as normal
        successors = engine.process(init_state)
        assert len(successors.successors) == 1
        final_state = successors.successors[0]
        assert final_state.regs.x0.concrete_value == 1
        assert final_state.regs.x1.concrete_value == 2
        assert final_state.addr == project.entry + 8  # After both instructions

    def test_breakpoint_simprocedure(self):
        """Test that breakpoints on SimProcedure locations work."""
        shellcode = "mov x0, 0x1; nop; mov x1, 0x2"  # nop will be hooked
        project = angr.load_shellcode(shellcode, "aarch64")

        # Hook the nop instruction
        @project.hook(project.entry + 4, length=4)
        def hook_nop(state):
            state.regs.x0 = 0x1337

        engine = UberIcicleEngine(project)  # UberIcicleEngine needed for hooks
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # Breakpoint is automatically added by UberIcicleEngine at hook_nop
        # Process up to the hook (which is also a breakpoint)
        succ1 = engine.process(init_state)  # Runs first mov
        assert len(succ1.successors) == 1
        state1 = succ1.successors[0]
        assert state1.addr == project.entry + 4  # At the hook
        assert state1.regs.x0.concrete_value == 1

        # Execute the hook
        succ2 = engine.process(state1)
        assert len(succ2.successors) == 1
        state2 = succ2.successors[0]
        assert state2.addr == project.entry + 8  # After the hook
        assert state2.regs.x0.concrete_value == 0x1337  # Value changed by hook

        # Execute the final mov
        succ3 = engine.process(state2)
        assert len(succ3.successors) == 1
        state3 = succ3.successors[0]
        assert state3.regs.x1.concrete_value == 2


class TestTracing(TestCase):
    """Tracing accuracy tests for the Icicle engine."""

    def test_tracing(self):
        project = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        init_state = project.factory.entry_state(
            stdin=b"username\nSOSNEAKY\n",
            args=["fauxware"],
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        emulator = angr.Emulator(UberIcicleEngine(project), init_state)

        stop_reason = emulator.run()

        assert stop_reason == EmulatorStopReason.EXIT
        assert list(emulator.state.history.bbl_addrs) == [
            0x400580,
            0x400580,
            0x400540,
            0x700018,
            0x4007E0,
            0x4007E0,
            0x4004E0,
            0x4005AC,
            0x4005BE,
            0x4004E9,
            0x400640,
            0x400660,
            0x4004EE,
            0x400880,
            0x4008AF,
            0x4004F3,
            0x400825,
            0x400846,
            0x801050,
            0x40071D,
            0x40071D,
            0x400510,
            0x700000,
            0x40073E,
            0x40073E,
            0x400530,
            0x700010,
            0x400754,
            0x400754,
            0x400530,
            0x700010,
            0x40076A,
            0x40076A,
            0x400510,
            0x700000,
            0x400774,
            0x400774,
            0x400530,
            0x700010,
            0x40078A,
            0x40078A,
            0x400530,
            0x700010,
            0x4007A0,
            0x4007A0,
            0x400664,
            0x400550,
            0x700020,
            0x40068E,
            0x40068E,
            0x400692,
            0x4006EB,
            0x4007B3,
            0x4007BD,
            0x4006ED,
            0x400510,
            0x700000,
            0x4006FB,
            0x4006FB,
            0x4007C7,
            0x4007D3,
            0x801058,
        ]


class TestEdgeHitmap(TestCase):
    """Unit tests for the edge_hitmap functionality in the Icicle engine."""

    def test_edge_hitmap_populated(self):
        """Test that the edge hitmap is populated after execution."""

        project = angr.load_shellcode("je $+2; nop; nop; nop", "x86_64")
        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
        )
        result = engine.process(init_state, num_inst=10)
        hitmap = result.successors[0].history.edge_hitmap

        assert hitmap is not None
        assert len(hitmap) == 65536
        assert any(x > 0 for x in hitmap)

    def test_edge_hitmap_reproducibility(self):
        project = angr.load_shellcode("nop; nop; nop; nop; nop", "x86_64")
        engine = IcicleEngine(project)

        state_1 = project.factory.blank_state(remove_options={*o.symbolic})
        result_1 = engine.process(state_1, num_inst=3)
        hitmap_1 = result_1.successors[0].history.edge_hitmap

        assert hitmap_1 is not None
        assert any(x > 0 for x in hitmap_1)

        state_2 = project.factory.blank_state(remove_options={*o.symbolic})
        result_2 = engine.process(state_2, num_inst=5)
        hitmap_2 = result_2.successors[0].history.edge_hitmap

        assert hitmap_1 == hitmap_2

    def test_edge_hitmap_multiple_blocks(self):
        shellcode = "xor rax, rax; inc rax; cmp rax, 5; jne $-8; nop"
        project = angr.load_shellcode(shellcode, "x86_64")
        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # Run a small number of instructions first
        result1 = engine.process(init_state, num_inst=5)
        s1 = result1.successors[0]
        hitmap1 = s1.history.edge_hitmap
        assert hitmap1 is not None
        assert any(x > 0 for x in hitmap1)
        assert s1.history.recent_instruction_count == 5
        print("Initial hitmap:", hitmap1[:100])

        # Continue execution for more instructions
        result2 = engine.process(s1, num_inst=45)
        s2 = result2.successors[0]
        hitmap2 = s2.history.edge_hitmap
        assert hitmap2 is not None
        assert any(x > 0 for x in hitmap2)
        assert s2.history.recent_instruction_count == 45
        print("Extended hitmap:", hitmap2[:100])

        # The second hitmap should be additive (all edges from first plus possibly more)
        bad = []
        for i in range(65536):
            if hitmap2[i] < hitmap1[i]:
                bad.append((i, hitmap1[i], hitmap2[i]))

        assert not bad, f"Edge hitmap values decreased for edges: {bad}"

    def test_fauxware_reproducibility(self):
        """Test that the edge hitmap is reproducible across runs of the fauxware binary."""
        project = angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)
        init_state = project.factory.entry_state(
            stdin=b"username\nSOSNEAKY\n",
            args=["fauxware"],
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        engine = UberIcicleEngine(project)

        state1 = init_state.copy()
        while state1.history.jumpkind != "Ijk_Exit":
            successors = engine.process(state1)
            assert len(successors.successors) == 1
            assert successors.successors[0].history.jumpkind != "Ijk_SigSEGV"
            state1 = successors.successors[0]

        hitmap1 = state1.history.last_edge_hitmap

        assert hitmap1 is not None
        assert any(x > 0 for x in hitmap1)

        # Reset and run again
        state2 = init_state.copy()
        while state2.history.jumpkind != "Ijk_Exit":
            successors = engine.process(state2)
            assert len(successors.successors) == 1
            assert successors.successors[0].history.jumpkind != "Ijk_SigSEGV"
            state2 = successors.successors[0]

        hitmap2 = state2.history.last_edge_hitmap

        assert hitmap1 == hitmap2

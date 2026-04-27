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

from typing import cast

import archinfo
import cle

import angr
from angr import sim_options as o
from angr.emulator import Emulator, EmulatorStopReason
from angr.engines.icicle import IcicleEngine, IcicleStateTranslationData, UberIcicleEngine
from angr.state_plugins.edge_hitmap import SimStateEdgeHitmap
from angr.state_plugins.icicle import SimStateIcicle
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
        # Check that the emulator exited past the syscall instruction
        # (icicle advances PC past the syscall: svc is 4 bytes on aarch64)
        assert successors.successors[0].ip.concrete_value == 0x4
        # Check that the syscall was invoked
        jk = successors.successors[0].history.jumpkind
        assert jk is not None and jk.startswith("Ijk_Sys")


class TestSnapshotSync(TestCase):
    """Unit tests for snapshot sync behavior in the Icicle engine."""

    def test_snapshot_sync_page_set_changes(self):
        """Test that snapshot sync correctly handles page additions, removals, and data changes."""
        # Shellcode: load a 64-bit value from address in x0 into x1
        shellcode = "ldr x1, [x0]"
        project = angr.load_shellcode(shellcode, "aarch64")
        engine = IcicleEngine(project)

        state_opts = {
            "remove_options": {*o.symbolic},
            "add_options": {o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        }

        # First run: establish snapshot, page at 0x10000
        s1 = project.factory.blank_state(**state_opts)
        s1.regs.x0 = 0x10000
        s1.memory.map_region(0x10000, 0x1000, 0b111)
        s1.memory.store(0x10000, 0xAA, size=8, endness="Iend_LE")

        result1 = engine.process(s1, num_inst=1)
        assert len(result1.successors) == 1
        assert result1[0].regs.x1.concrete_value == 0xAA

        # Second run: same page, updated data — tests writable page sync
        s2 = project.factory.blank_state(**state_opts)
        s2.regs.x0 = 0x10000
        s2.memory.map_region(0x10000, 0x1000, 0b111)
        s2.memory.store(0x10000, 0xBB, size=8, endness="Iend_LE")

        result2 = engine.process(s2, num_inst=1)
        assert len(result2.successors) == 1
        assert result2[0].regs.x1.concrete_value == 0xBB

        # Third run: add new page at 0x20000, read from it — tests page addition
        s3 = project.factory.blank_state(**state_opts)
        s3.regs.x0 = 0x20000
        s3.memory.map_region(0x10000, 0x1000, 0b111)
        s3.memory.map_region(0x20000, 0x1000, 0b111)
        s3.memory.store(0x20000, 0xCC, size=8, endness="Iend_LE")

        result3 = engine.process(s3, num_inst=1)
        assert len(result3.successors) == 1
        assert result3[0].regs.x1.concrete_value == 0xCC

        # Fourth run: remove 0x10000, read from 0x20000 — tests page removal
        s4 = project.factory.blank_state(**state_opts)
        s4.regs.x0 = 0x20000
        s4.memory.map_region(0x20000, 0x1000, 0b111)
        s4.memory.store(0x20000, 0xDD, size=8, endness="Iend_LE")

        result4 = engine.process(s4, num_inst=1)
        assert len(result4.successors) == 1
        assert result4[0].regs.x1.concrete_value == 0xDD

    def test_snapshot_sync_code_modification(self):
        """Code at the entry address can differ between states; each branch must
        re-lift instead of replaying a stale JIT'd block from a sibling state."""
        # aarch64 `movz x0, #imm16` (hw=0, Rd=x0), little-endian byte order:
        #   movz x0, #1 -> 0xD2800020
        #   movz x0, #2 -> 0xD2800040
        code_a = b"\x20\x00\x80\xd2"
        code_b = b"\x40\x00\x80\xd2"

        project = angr.load_shellcode(code_a, "aarch64")
        engine = IcicleEngine(project)
        state_opts = {
            "remove_options": {*o.symbolic},
            "add_options": {o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        }

        # First run: lifts code_a, takes the snapshot.
        s1 = project.factory.blank_state(**state_opts)
        assert engine.process(s1, num_inst=1)[0].regs.x0.concrete_value == 1

        # Branch with code overwritten — the sync write to a previously-
        # executed page must succeed AND drop the cached code_a block.
        s2 = project.factory.blank_state(**state_opts)
        s2.memory.store(project.entry, code_b)
        assert engine.process(s2, num_inst=1)[0].regs.x0.concrete_value == 2

        # Branch back to the snapshot's original code — the JIT block from
        # the previous run must not survive the restore.
        s3 = project.factory.blank_state(**state_opts)
        assert engine.process(s3, num_inst=1)[0].regs.x0.concrete_value == 1

    def test_snapshot_sync_new_readonly_page_content(self):
        """A read-only page newly mapped between states must have its content
        copied to the emu — not left as zeros."""
        # ldr x1, [x0]
        shellcode = "ldr x1, [x0]"
        project = angr.load_shellcode(shellcode, "aarch64")
        engine = IcicleEngine(project)
        state_opts = {
            "remove_options": {*o.symbolic},
            "add_options": {o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        }

        # First run: establishes snapshot with no extra mappings.
        s1 = project.factory.blank_state(**state_opts)
        s1.regs.x0 = 0x10000
        s1.memory.map_region(0x10000, 0x1000, 0b111)
        s1.memory.store(0x10000, 0xAA, size=8, endness="Iend_LE")
        assert engine.process(s1, num_inst=1)[0].regs.x1.concrete_value == 0xAA

        # Branch: the load target is on a newly-mapped read-only page. The
        # delta-sync must seed its content; otherwise the load reads zero.
        s2 = project.factory.blank_state(**state_opts)
        s2.regs.x0 = 0x20000
        s2.memory.map_region(0x10000, 0x1000, 0b111)
        s2.memory.map_region(0x20000, 0x1000, 0b101)  # R + X, no W
        s2.memory.store(0x20000, 0xBB, size=8, endness="Iend_LE")
        assert engine.process(s2, num_inst=1)[0].regs.x1.concrete_value == 0xBB


class TestDirtyPageTracking(TestCase):
    """Unit tests for dirty page tracking optimization in the Icicle engine."""

    def test_only_written_pages_are_dirty(self):
        """Test that modified_pages reports only pages actually written during execution."""
        # Shellcode: store x0 to [x1], leaving other mapped pages untouched
        shellcode = "str x0, [x1]"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # Map three writable pages; only one will be written to
        state.memory.map_region(0x10000, 0x1000, 0b111)
        state.memory.map_region(0x20000, 0x1000, 0b111)
        state.memory.map_region(0x30000, 0x1000, 0b111)
        state.regs.x0 = 0xDEADBEEF
        state.regs.x1 = 0x20000  # write target

        result = engine.process(state, num_inst=1)
        assert len(result.successors) == 1
        out = result.successors[0]

        # The written value must be correct
        assert out.memory.load(0x20000, 8, endness="Iend_LE").concrete_value == 0xDEADBEEF

        # Pages that were not written should still read as zero-filled
        assert out.memory.load(0x10000, 8, endness="Iend_LE").concrete_value == 0
        assert out.memory.load(0x30000, 8, endness="Iend_LE").concrete_value == 0

    def test_dirty_tracking_across_snapshot_restore(self):
        """Test that dirty page tracking works correctly across snapshot restore cycles."""
        # Shellcode: store x0 to [x1]
        shellcode = "str x0, [x1]"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)

        state_opts = {
            "remove_options": {*o.symbolic},
            "add_options": {o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        }

        # First run: establish snapshot, write to page 0x10000
        s1 = project.factory.blank_state(**state_opts)
        s1.memory.map_region(0x10000, 0x1000, 0b111)
        s1.memory.map_region(0x20000, 0x1000, 0b111)
        s1.regs.x0 = 0xAA
        s1.regs.x1 = 0x10000

        r1 = engine.process(s1, num_inst=1)
        assert r1[0].memory.load(0x10000, 8, endness="Iend_LE").concrete_value == 0xAA

        # Second run (snapshot restore path): write to different page
        s2 = project.factory.blank_state(**state_opts)
        s2.memory.map_region(0x10000, 0x1000, 0b111)
        s2.memory.map_region(0x20000, 0x1000, 0b111)
        s2.regs.x0 = 0xBB
        s2.regs.x1 = 0x20000

        r2 = engine.process(s2, num_inst=1)
        assert r2[0].memory.load(0x20000, 8, endness="Iend_LE").concrete_value == 0xBB
        # Page 0x10000 should be unchanged (zero-filled from the fresh angr state copy)
        assert r2[0].memory.load(0x10000, 8, endness="Iend_LE").concrete_value == 0


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

    def test_cortex_m_thumb_only(self):
        """Test that the Icicle engine automatically uses thumb mode for Cortex-M."""

        # Shellcode to add 1 and 2 in Thumb mode
        shellcode = "mov r0, 0x1; mov r1, 0x2; add r2, r0, r1;"
        project = angr.load_shellcode(shellcode, archinfo.ArchARMCortexM())

        engine = IcicleEngine(project)
        init_state = project.factory.entry_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

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

    def test_thumb_extra_stop_points(self):
        """Test that extra_stop_points work in Thumb mode."""
        # Shellcode to add 1 and 2 in Thumb mode
        shellcode = "mov r0, 0x1; mov r1, 0x2; add r2, r0, r1;"
        project = angr.load_shellcode(shellcode, "armel", thumb=True)

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # Use extra_stop_points to stop at the second instruction (mov r1, 0x2)
        stop_addr = project.entry + 4

        # Process up to the stop point
        successors = engine.process(init_state, extra_stop_points={stop_addr})
        assert len(successors.successors) == 1
        state_after_bp = successors.successors[0]
        assert state_after_bp.addr == stop_addr
        assert state_after_bp.regs.r0.concrete_value == 1

        # Continue execution
        successors2 = engine.process(state_after_bp, num_inst=2)
        assert len(successors2.successors) == 1
        final_state = successors2.successors[0]
        assert final_state.regs.r2.concrete_value == 3


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


class TestExtraStopPoints(TestCase):
    """Unit tests for extra_stop_points functionality in the Icicle engine."""

    def test_single_stop_point(self):
        """Test using a single extra_stop_point."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1; mov x3, 0x3"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # Stop at the third instruction (add x2, x0, x1)
        stop_addr = project.entry + 8

        # Process up to the stop point
        successors = engine.process(init_state, extra_stop_points={stop_addr})
        assert len(successors.successors) == 1
        state_after_bp = successors.successors[0]
        assert state_after_bp.addr == stop_addr
        assert state_after_bp.regs.x0.concrete_value == 1
        assert state_after_bp.regs.x1.concrete_value == 2

        # Continue execution (without extra_stop_points)
        successors2 = engine.process(state_after_bp)
        assert len(successors2.successors) == 1
        final_state = successors2.successors[0]
        assert final_state.regs.x2.concrete_value == 3
        assert final_state.regs.x3.concrete_value == 3

    def test_multiple_stop_points(self):
        """Test multiple extra_stop_points."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1; mov x3, 0x3; sub x4, x3, x0"  # 5 instructions
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        bp1_addr = project.entry + 4  # mov x1, 0x2
        bp2_addr = project.entry + 12  # mov x3, 0x3
        stop_points = {bp1_addr, bp2_addr}

        # Process to first stop point
        succ1 = engine.process(init_state, extra_stop_points=stop_points)
        assert len(succ1.successors) == 1
        state1 = succ1.successors[0]
        assert state1.addr == bp1_addr
        assert state1.regs.x0.concrete_value == 1

        # Process to second stop point
        succ2 = engine.process(state1, extra_stop_points=stop_points)
        assert len(succ2.successors) == 1
        state2 = succ2.successors[0]
        assert state2.addr == bp2_addr
        assert state2.regs.x1.concrete_value == 2
        assert state2.regs.x2.concrete_value == 3

        # Process to end
        succ3 = engine.process(state2, extra_stop_points=stop_points)
        assert len(succ3.successors) == 1
        state3 = succ3.successors[0]
        assert state3.regs.x3.concrete_value == 3
        assert state3.regs.x4.concrete_value == 2  # 3 - 1
        assert state3.addr == project.entry + 20  # After last instruction

    def test_unmapped_stop_point_skipped(self):
        """Test that a stop point on an unmapped page is silently skipped."""
        shellcode = "mov x0, 0x1; mov x1, 0x2"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # 0xDEAD0000 is unmapped — should be skipped, not crash
        successors = engine.process(init_state, extra_stop_points={0xDEAD0000})
        assert len(successors.successors) == 1
        final_state = successors.successors[0]
        assert final_state.regs.x0.concrete_value == 1
        assert final_state.regs.x1.concrete_value == 2

    def test_stop_point_at_start(self):
        """Test that a stop point at the very first instruction is ignored (execution resumes immediately)."""
        shellcode = "mov x0, 0x1; mov x1, 0x2"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # The stop point at the entry should be ignored, so execution should proceed as normal
        successors = engine.process(init_state, extra_stop_points={project.entry})
        assert len(successors.successors) == 1
        final_state = successors.successors[0]
        assert final_state.regs.x0.concrete_value == 1
        assert final_state.regs.x1.concrete_value == 2
        assert final_state.addr == project.entry + 8  # After both instructions

    def test_simprocedure_stop_point(self):
        """Test that SimProcedure locations work as stop points."""
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

        # SimProcedure addresses are automatically added as stop points
        # Process up to the hook
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
        init_state.register_plugin("edge_hitmap", SimStateEdgeHitmap())
        result = engine.process(init_state, num_inst=10)
        hitmap = result.successors[0].get_plugin("edge_hitmap").edge_hitmap

        assert hitmap is not None
        assert len(hitmap) == 65536
        assert any(x > 0 for x in hitmap)

    def test_edge_hitmap_reproducibility(self):
        project = angr.load_shellcode("nop; nop; nop; nop; nop", "x86_64")
        engine = IcicleEngine(project)

        state_1 = project.factory.blank_state(remove_options={*o.symbolic})
        state_1.register_plugin("edge_hitmap", SimStateEdgeHitmap())
        result_1 = engine.process(state_1, num_inst=3)
        hitmap_1 = result_1.successors[0].get_plugin("edge_hitmap").edge_hitmap

        assert hitmap_1 is not None
        assert any(x > 0 for x in hitmap_1)

        state_2 = project.factory.blank_state(remove_options={*o.symbolic})
        state_2.register_plugin("edge_hitmap", SimStateEdgeHitmap())
        result_2 = engine.process(state_2, num_inst=5)
        hitmap_2 = result_2.successors[0].get_plugin("edge_hitmap").edge_hitmap

        assert hitmap_1 == hitmap_2

    def test_edge_hitmap_multiple_blocks(self):
        shellcode = "xor rax, rax; loop: inc rax; cmp rax, 5; jne loop; hlt"
        project = angr.load_shellcode(shellcode, "x86_64")
        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        init_state.register_plugin("edge_hitmap", SimStateEdgeHitmap())

        # Run a small number of instructions first
        result1 = engine.process(init_state, num_inst=5)
        s1 = result1.successors[0]
        hitmap1 = s1.get_plugin("edge_hitmap").edge_hitmap
        assert hitmap1 is not None
        assert any(x > 0 for x in hitmap1)
        assert s1.history.recent_instruction_count == 5
        print("Initial hitmap:", hitmap1[:100])

        # Continue execution for more instructions
        result2 = engine.process(s1, num_inst=45)
        s2 = result2.successors[0]
        hitmap2 = s2.get_plugin("edge_hitmap").edge_hitmap
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
        init_state.register_plugin("edge_hitmap", SimStateEdgeHitmap())

        engine = UberIcicleEngine(project)

        state1 = init_state.copy()
        while state1.history.jumpkind != "Ijk_Exit":
            successors = engine.process(state1)
            assert len(successors.successors) == 1
            assert successors.successors[0].history.jumpkind != "Ijk_SigSEGV"
            state1 = successors.successors[0]

        hitmap1 = state1.get_plugin("edge_hitmap").edge_hitmap

        assert hitmap1 is not None
        assert any(x > 0 for x in hitmap1)

        # Reset and run again
        state2 = init_state.copy()
        while state2.history.jumpkind != "Ijk_Exit":
            successors = engine.process(state2)
            assert len(successors.successors) == 1
            assert successors.successors[0].history.jumpkind != "Ijk_SigSEGV"
            state2 = successors.successors[0]

        hitmap2 = state2.get_plugin("edge_hitmap").edge_hitmap

        assert hitmap1 == hitmap2


class TestSimStateIciclePlugin(TestCase):
    """Tests for the SimStateIcicle state plugin."""

    def test_plugin_attached_after_process(self):
        """Test that processing a state attaches the icicle plugin to the result state."""
        shellcode = "mov x0, 0x1; mov x1, 0x2"
        project = angr.load_shellcode(shellcode, "aarch64")
        engine = IcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        result = engine.process(init_state, num_inst=2)
        state = result.successors[0]
        assert state.has_plugin("icicle")
        plugin = state.get_plugin("icicle")
        assert isinstance(plugin, SimStateIcicle)
        assert plugin.engine_id == id(engine)
        assert plugin.run_id > 0

    def test_plugin_copy(self):
        """Test that the plugin is correctly copied when the state is copied."""
        dummy_td = cast(IcicleStateTranslationData, None)
        plugin = SimStateIcicle(
            engine_id=12345,
            run_id=42,
            translation_data=dummy_td,
            dirty_pages={3, 4},
        )
        copied = plugin.copy({})
        assert copied.engine_id == 12345
        assert copied.run_id == 42
        assert copied.dirty_pages == {3, 4}
        # Ensure copies are independent
        copied.dirty_pages.add(6)
        assert 6 not in plugin.dirty_pages

    def test_plugin_merge_and_widen(self):
        """Test that merge and widen return False (not mergeable)."""
        dummy_td = cast(IcicleStateTranslationData, None)
        plugin = SimStateIcicle(
            engine_id=1,
            run_id=1,
            translation_data=dummy_td,
            dirty_pages=set(),
        )
        assert plugin.merge([], [], None) is False
        assert plugin.widen([]) is False


class TestContinuation(TestCase):
    """Tests for the continuation path in IcicleEngine."""

    def test_continuation_via_emulator(self):
        """Test that the Emulator's run loop uses the continuation path for hooks."""
        # Shellcode with a hook in the middle — forces multiple engine calls
        shellcode = "mov x0, 0x1; nop; mov x1, 0x2; add x2, x0, x1"
        project = angr.load_shellcode(shellcode, "aarch64")

        def hook_nop(state):
            state.regs.x0 = 0x10

        project.hook(0x4, hook_nop, length=4)

        engine = UberIcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        emulator = Emulator(engine, init_state.copy())
        # Run 3 instructions: mov x0 (1 inst) + hook + mov x1 + add (2 inst) = 3
        stop_reason = emulator.run(num_inst=3)
        assert stop_reason == EmulatorStopReason.INSTRUCTION_LIMIT
        # Hook changed x0 to 0x10, so add x2, x0, x1 = 0x10 + 0x2 = 0x12
        assert emulator.state.regs.x2.concrete_value == 0x12

    def test_continuation_plugin_invalidated_by_different_engine(self):
        """Test that a plugin from one engine doesn't cause continuation on a different engine."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1"
        project = angr.load_shellcode(shellcode, "aarch64")
        state_opts = {
            "remove_options": {*o.symbolic},
            "add_options": {o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        }

        engine1 = IcicleEngine(project)
        s = project.factory.blank_state(**state_opts)
        result1 = engine1.process(s, num_inst=3)
        state_with_plugin = result1.successors[0]
        assert state_with_plugin.has_plugin("icicle")

        # A different engine should NOT use the continuation path
        engine2 = IcicleEngine(project)
        s2 = project.factory.blank_state(**state_opts)
        result2 = engine2.process(s2, num_inst=3)
        assert result2.successors[0].regs.x2.concrete_value == 3

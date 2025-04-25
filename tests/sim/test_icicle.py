"""
test_icicle.py - Unit tests for the Icicle engine in angr.

These tests are broken into two classes: TestIcicle and TestFauxware. TestIcicle
contains unit tests for basic functionality of the engine. TestFauxware contains
integration tests for running the fauxware binary using the engine.
"""
# pylint: disable=no-self-use

from __future__ import annotations

import os
from unittest import TestCase

import angr
from angr import sim_options as o
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
        init_state.memory.map_region(0x0, 0x1000, 0o000)

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

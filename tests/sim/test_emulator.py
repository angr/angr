"""
test_emulator.py - Unit tests for the Emulator class in angr.

These tests mirror TestFauxware and TestBreakpoints from test_icicle.py, but use the Emulator interface.
"""

from __future__ import annotations

import os
from unittest import TestCase

import angr
from angr import sim_options as o
from angr.emulator import Emulator, EmulatorStopReason
from angr.engines.icicle import UberIcicleEngine
from tests.common import bin_location

# pylint: disable=no-self-use


class TestFauxware(TestCase):
    """Integration tests executing the fauxware binary using the Emulator class."""

    def _run_fauxware(self, arch):
        project = angr.Project(os.path.join(bin_location, "tests", arch, "fauxware"), auto_load_libs=False)
        init_state = project.factory.entry_state(
            stdin=b"username\nSOSNEAKY\n",
            args=["fauxware"],
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )
        engine = UberIcicleEngine(project)
        emulator = Emulator(engine, init_state.copy())

        stop_reason = emulator.run()
        assert stop_reason == EmulatorStopReason.EXIT

        # Check that the program has printed the expected output
        assert b"Welcome to the admin console, trusted user!\n" in emulator.state.posix.dumps(1)

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
    """Unit tests for breakpoint functionality in the Emulator class."""

    def test_add_breakpoint(self):
        """Test adding and hitting a breakpoint."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1; mov x3, 0x3"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = UberIcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        emulator = Emulator(engine, init_state.copy())

        # Add breakpoint at the third instruction (add x2, x0, x1)
        breakpoint_addr = project.entry + 8
        emulator.add_breakpoint(breakpoint_addr)

        # Run until breakpoint
        stop_reason = emulator.run()
        assert stop_reason == EmulatorStopReason.BREAKPOINT
        assert emulator.state.addr == breakpoint_addr
        assert emulator.state.regs.x0.concrete_value == 1
        assert emulator.state.regs.x1.concrete_value == 2

        # Continue execution with instruction limit
        stop_reason = emulator.run(num_inst=2)
        assert stop_reason == EmulatorStopReason.INSTRUCTION_LIMIT
        assert emulator.state.regs.x2.concrete_value == 3
        assert emulator.state.regs.x3.concrete_value == 3

    def test_remove_breakpoint(self):
        """Test removing a breakpoint."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1; mov x3, 0x3"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = UberIcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        emulator = Emulator(engine, init_state.copy())

        breakpoint_addr = project.entry + 8  # add x2, x0, x1
        emulator.add_breakpoint(breakpoint_addr)
        emulator.remove_breakpoint(breakpoint_addr)

        # Run all instructions, breakpoint should not be hit
        stop_reason = emulator.run(num_inst=4)
        assert stop_reason == EmulatorStopReason.INSTRUCTION_LIMIT
        assert emulator.state.regs.x2.concrete_value == 3
        assert emulator.state.regs.x3.concrete_value == 3

    def test_multiple_breakpoints(self):
        """Test multiple breakpoints."""
        shellcode = "mov x0, 0x1; mov x1, 0x2; add x2, x0, x1; mov x3, 0x3; sub x4, x3, x0"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = UberIcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        emulator = Emulator(engine, init_state.copy())

        bp1_addr = project.entry + 4  # mov x1, 0x2
        bp2_addr = project.entry + 12  # mov x3, 0x3
        emulator.add_breakpoint(bp1_addr)
        emulator.add_breakpoint(bp2_addr)

        # Run to first breakpoint
        stop_reason = emulator.run()
        assert stop_reason == EmulatorStopReason.BREAKPOINT
        assert emulator.state.addr == bp1_addr
        assert emulator.state.regs.x0.concrete_value == 1

        # Run to second breakpoint
        stop_reason = emulator.run()
        assert stop_reason == EmulatorStopReason.BREAKPOINT
        assert emulator.state.addr == bp2_addr
        assert emulator.state.regs.x1.concrete_value == 2
        assert emulator.state.regs.x2.concrete_value == 3

        # Run to end
        stop_reason = emulator.run(num_inst=2)
        assert stop_reason == EmulatorStopReason.INSTRUCTION_LIMIT
        assert emulator.state.regs.x3.concrete_value == 3
        assert emulator.state.regs.x4.concrete_value == 2  # 3 - 1

    def test_breakpoint_at_start(self):
        """Test that a breakpoint at the very first instruction is ignored (execution resumes immediately)."""
        shellcode = "mov x0, 0x1; mov x1, 0x2"
        project = angr.load_shellcode(shellcode, "aarch64")

        engine = UberIcicleEngine(project)
        init_state = project.factory.blank_state(
            remove_options={*o.symbolic},
            add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        emulator = Emulator(engine, init_state.copy())
        emulator.add_breakpoint(project.entry)

        # The breakpoint at the entry should be ignored, so execution should proceed as normal
        stop_reason = emulator.run(num_inst=2)
        assert stop_reason == EmulatorStopReason.INSTRUCTION_LIMIT
        assert emulator.state.regs.x0.concrete_value == 1
        assert emulator.state.regs.x1.concrete_value == 2

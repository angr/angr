"""Tests for angr's core_state() factory method.

These tests verify that core_state() correctly restores register state and memory
from ELF core dump files, using a simple crasher binary that segfaults on a null
pointer dereference.

The crasher binary (tests/cores/crasher) is compiled from tests/cores/crasher.c:
  - Sets global_marker = 0xBEEF
  - Calls do_crash(NULL) which dereferences NULL, causing SIGSEGV
  - At crash: RIP = 0x4011a6 (inside do_crash), RDI = 0

Core dumps tested:
  - crasher_segfault.core: Natural segfault core (ulimit -c unlimited)
  - crasher_gdb.core: GDB gcore output
  - crasher_qemu.core: QEMU-user core dump (if available)
"""

import os
import unittest

import angr


CORES_DIR = os.path.join(os.path.dirname(__file__), "cores")
CRASHER_BIN = os.path.join(CORES_DIR, "crasher")
SEGFAULT_CORE = os.path.join(CORES_DIR, "crasher_segfault.core")
GDB_CORE = os.path.join(CORES_DIR, "crasher_gdb.core")
QEMU_CORE = os.path.join(CORES_DIR, "crasher_qemu.core")

# Known values from the crasher binary / core dumps
CRASH_ADDR = 0x4011A6  # Address of the faulting instruction in do_crash
DO_CRASH_ADDR = 0x401196  # Start of do_crash function
MAIN_ADDR = 0x4011AF  # Start of main function
GLOBAL_MARKER_ADDR = 0x404030  # Address of global_marker variable
GLOBAL_MARKER_VAL = 0xBEEF  # Value set before crash


class TestCoreStateSegfault(unittest.TestCase):
    """Test core_state() with a natural segfault core dump."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(SEGFAULT_CORE):
            raise unittest.SkipTest("Segfault core not available")
        cls.project = angr.Project(CRASHER_BIN)
        cls.state = cls.project.factory.core_state(SEGFAULT_CORE)

    def test_rip_at_crash_site(self):
        """RIP should point to the faulting instruction."""
        rip = self.state.solver.eval(self.state.regs.rip)
        self.assertEqual(rip, CRASH_ADDR)

    def test_rdi_is_null(self):
        """RDI should be 0 (the NULL pointer passed to do_crash)."""
        rdi = self.state.solver.eval(self.state.regs.rdi)
        self.assertEqual(rdi, 0)

    def test_rsp_is_reasonable(self):
        """RSP should point to a valid stack address (high canonical address)."""
        rsp = self.state.solver.eval(self.state.regs.rsp)
        # Stack addresses are typically in the 0x7fff... range on x86_64
        self.assertGreater(rsp, 0x7F0000000000)

    def test_text_readable(self):
        """Should be able to read .text from the original binary."""
        # Read the first byte at the crash site
        val = self.state.solver.eval(self.state.memory.load(CRASH_ADDR, 1))
        # The instruction at 0x4011a6 is "mov dword ptr [rax], 0x2a"
        # which starts with 0xC7 (199 decimal)
        self.assertEqual(val, 0xC7)

    def test_global_marker(self):
        """global_marker should be 0xBEEF (modified before crash)."""
        val = self.state.solver.eval(self.state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE"))
        self.assertEqual(val, GLOBAL_MARKER_VAL)

    def test_stack_readable(self):
        """Should be able to read stack memory."""
        rsp = self.state.solver.eval(self.state.regs.rsp)
        # Read 8 bytes from the stack - should be concrete, not symbolic
        val = self.state.memory.load(rsp, 8, endness="Iend_LE")
        self.assertTrue(self.state.solver.is_true(val == self.state.solver.eval(val)))

    def test_symbols_available(self):
        """Symbols from the binary should be available."""
        do_crash_sym = self.project.loader.find_symbol("do_crash")
        self.assertIsNotNone(do_crash_sym)
        self.assertEqual(do_crash_sym.rebased_addr, DO_CRASH_ADDR)

        main_sym = self.project.loader.find_symbol("main")
        self.assertIsNotNone(main_sym)
        self.assertEqual(main_sym.rebased_addr, MAIN_ADDR)

    def test_disassembly_at_crash(self):
        """Should be able to disassemble at the crash location."""
        block = self.project.factory.block(CRASH_ADDR)
        self.assertGreater(len(block.capstone.insns), 0)

    def test_simgr_creation(self):
        """Should be able to create a simulation manager from the core state."""
        simgr = self.project.factory.simgr(self.state)
        self.assertEqual(len(simgr.active), 1)


class TestCoreStateGDB(unittest.TestCase):
    """Test core_state() with a GDB gcore dump."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(GDB_CORE):
            raise unittest.SkipTest("GDB core not available")
        cls.project = angr.Project(CRASHER_BIN)
        cls.state = cls.project.factory.core_state(GDB_CORE)

    def test_rip_at_crash_site(self):
        """RIP should point to the faulting instruction."""
        rip = self.state.solver.eval(self.state.regs.rip)
        self.assertEqual(rip, CRASH_ADDR)

    def test_rdi_is_null(self):
        """RDI should be 0."""
        rdi = self.state.solver.eval(self.state.regs.rdi)
        self.assertEqual(rdi, 0)

    def test_rsp_is_reasonable(self):
        """RSP should point to a valid stack address."""
        rsp = self.state.solver.eval(self.state.regs.rsp)
        self.assertGreater(rsp, 0x7F0000000000)

    def test_text_readable(self):
        """Should be able to read .text from the original binary."""
        val = self.state.solver.eval(self.state.memory.load(CRASH_ADDR, 1))
        self.assertEqual(val, 0xC7)

    def test_global_marker(self):
        """global_marker should be 0xBEEF."""
        val = self.state.solver.eval(self.state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE"))
        self.assertEqual(val, GLOBAL_MARKER_VAL)

    def test_stack_readable(self):
        """Should be able to read stack memory."""
        rsp = self.state.solver.eval(self.state.regs.rsp)
        val = self.state.memory.load(rsp, 8, endness="Iend_LE")
        self.assertTrue(self.state.solver.is_true(val == self.state.solver.eval(val)))

    def test_simgr_creation(self):
        """Should be able to create a simulation manager from the core state."""
        simgr = self.project.factory.simgr(self.state)
        self.assertEqual(len(simgr.active), 1)


class TestCoreStateNecessity(unittest.TestCase):
    """Demonstrate that core_state() is necessary.

    The standard angr API (blank_state, entry_state, etc.) does NOT restore
    register state or runtime memory from a core dump. This test class shows
    what's missing when you try to use the standard API with a core dump, and
    then shows that core_state() fixes each problem.
    """

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(SEGFAULT_CORE):
            raise unittest.SkipTest("Segfault core not available")
        cls.project = angr.Project(CRASHER_BIN)

    def test_blank_state_rip_not_at_crash(self):
        """blank_state does NOT set RIP to the crash location."""
        state = self.project.factory.blank_state()
        rip = state.solver.eval(state.regs.rip)
        # blank_state starts at the entry point, not the crash site
        self.assertNotEqual(rip, CRASH_ADDR)

    def test_blank_state_rdi_not_restored(self):
        """blank_state does NOT restore RDI from the core dump."""
        state = self.project.factory.blank_state()
        # RDI is symbolic in a blank state, not the concrete 0 from the core
        self.assertTrue(state.regs.rdi.symbolic)

    def test_blank_state_stack_symbolic(self):
        """blank_state stack memory is symbolic, not concrete core dump data."""
        state = self.project.factory.blank_state()
        rsp = state.solver.eval(state.regs.rsp)
        val = state.memory.load(rsp, 8)
        # Stack is symbolic in blank_state, not concrete data from the core
        self.assertTrue(val.symbolic)

    def test_blank_state_global_marker_not_updated(self):
        """blank_state has the initial .data value (0xDEAD), not the runtime value (0xBEEF).

        The core dump contains the runtime value of global_marker (0xBEEF),
        which was modified before the crash. blank_state only has the original
        binary's .data segment with the initial value 0xDEAD.
        """
        state = self.project.factory.blank_state()
        val = state.solver.eval(state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE"))
        # blank_state has the compile-time value, not the runtime value
        self.assertEqual(val, 0xDEAD)
        self.assertNotEqual(val, GLOBAL_MARKER_VAL)

    def test_core_state_fixes_rip(self):
        """core_state() correctly sets RIP to the crash location."""
        state = self.project.factory.core_state(SEGFAULT_CORE)
        rip = state.solver.eval(state.regs.rip)
        self.assertEqual(rip, CRASH_ADDR)

    def test_core_state_fixes_registers(self):
        """core_state() correctly restores concrete register values."""
        state = self.project.factory.core_state(SEGFAULT_CORE)
        # RDI is concrete 0 (the NULL pointer), not symbolic
        self.assertFalse(state.regs.rdi.symbolic)
        self.assertEqual(state.solver.eval(state.regs.rdi), 0)

    def test_core_state_fixes_stack(self):
        """core_state() restores concrete stack memory from the core dump."""
        state = self.project.factory.core_state(SEGFAULT_CORE)
        rsp = state.solver.eval(state.regs.rsp)
        val = state.memory.load(rsp, 8, endness="Iend_LE")
        # Stack is concrete, not symbolic
        self.assertTrue(state.solver.is_true(val == state.solver.eval(val)))

    def test_core_state_fixes_global_marker(self):
        """core_state() has the runtime value of global_marker (0xBEEF)."""
        state = self.project.factory.core_state(SEGFAULT_CORE)
        val = state.solver.eval(state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE"))
        self.assertEqual(val, GLOBAL_MARKER_VAL)


class TestCoreStateQEMU(unittest.TestCase):
    """Test core_state() with a QEMU-user core dump.

    QEMU-user core dumps have documented quirks:
      - Registers in NT_PRSTATUS are the QEMU *host* process registers, NOT the
        emulated guest registers. This is because the kernel dumps the QEMU process
        itself, not the emulated program.
      - Memory mappings include both guest and host segments. Guest binary segments
        are mapped at the expected guest virtual addresses (e.g., 0x400000 for a
        no-PIE binary), so .text/.data are accessible at the correct addresses.
      - The guest stack is at QEMU's default base (0x2aaaa...) instead of the
        native 0x7fff... range.
      - Core file sizes can be very large (100+ MB) because the QEMU JIT cache
        and host libraries are included. The test core is trimmed to guest-only
        segments.
    """

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(QEMU_CORE):
            raise unittest.SkipTest("QEMU core not available")
        cls.project = angr.Project(CRASHER_BIN)
        cls.state = cls.project.factory.core_state(QEMU_CORE)

    def test_loads_without_error(self):
        """core_state() should load a QEMU core without raising exceptions."""
        self.assertIsNotNone(self.state)

    def test_registers_are_concrete(self):
        """Registers should be concrete values (from the core's NT_PRSTATUS)."""
        self.assertFalse(self.state.regs.rip.symbolic)
        self.assertFalse(self.state.regs.rsp.symbolic)

    def test_rip_is_qemu_host_not_guest(self):
        """RIP contains a QEMU host address, NOT the guest crash address.

        This is a known QEMU-user limitation: the kernel dumps the QEMU host
        process, so registers reflect QEMU's own execution state.
        """
        rip = self.state.solver.eval(self.state.regs.rip)
        self.assertNotEqual(rip, CRASH_ADDR)

    def test_text_readable(self):
        """Guest .text is accessible at the original binary's address."""
        val = self.state.solver.eval(self.state.memory.load(CRASH_ADDR, 1))
        self.assertEqual(val, 0xC7)

    def test_global_marker(self):
        """global_marker should be 0xBEEF (runtime value from guest memory)."""
        val = self.state.solver.eval(
            self.state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE")
        )
        self.assertEqual(val, GLOBAL_MARKER_VAL)

    def test_symbols_available(self):
        """Symbols from the original binary should be available."""
        do_crash_sym = self.project.loader.find_symbol("do_crash")
        self.assertIsNotNone(do_crash_sym)
        self.assertEqual(do_crash_sym.rebased_addr, DO_CRASH_ADDR)

    def test_disassembly_at_crash(self):
        """Should be able to disassemble at the crash location."""
        block = self.project.factory.block(CRASH_ADDR)
        self.assertGreater(len(block.capstone.insns), 0)

    def test_simgr_creation(self):
        """Should be able to create a simulation manager from the QEMU core state."""
        simgr = self.project.factory.simgr(self.state)
        self.assertEqual(len(simgr.active), 1)


class TestCoreStateErrors(unittest.TestCase):
    """Test error handling in core_state()."""

    def test_non_core_file_raises_error(self):
        """Passing a non-core ELF should raise AngrError."""
        p = angr.Project(CRASHER_BIN)
        with self.assertRaises(angr.errors.AngrError):
            p.factory.core_state(CRASHER_BIN)


class TestCoreStateCrossCore(unittest.TestCase):
    """Cross-core-type comparisons to verify consistency."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(SEGFAULT_CORE) or not os.path.exists(GDB_CORE):
            raise unittest.SkipTest("Both core types required")
        cls.project = angr.Project(CRASHER_BIN)
        cls.segfault_state = cls.project.factory.core_state(SEGFAULT_CORE)
        cls.gdb_state = cls.project.factory.core_state(GDB_CORE)

    def test_rip_matches(self):
        """Both cores should have the same RIP (crash at same instruction)."""
        rip_seg = self.segfault_state.solver.eval(self.segfault_state.regs.rip)
        rip_gdb = self.gdb_state.solver.eval(self.gdb_state.regs.rip)
        self.assertEqual(rip_seg, rip_gdb)

    def test_rdi_matches(self):
        """Both cores should have RDI=0."""
        rdi_seg = self.segfault_state.solver.eval(self.segfault_state.regs.rdi)
        rdi_gdb = self.gdb_state.solver.eval(self.gdb_state.regs.rdi)
        self.assertEqual(rdi_seg, rdi_gdb)

    def test_global_marker_matches(self):
        """Both cores should have global_marker=0xBEEF."""
        val_seg = self.segfault_state.solver.eval(
            self.segfault_state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE")
        )
        val_gdb = self.gdb_state.solver.eval(
            self.gdb_state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE")
        )
        self.assertEqual(val_seg, val_gdb)
        self.assertEqual(val_seg, GLOBAL_MARKER_VAL)


class TestCoreStateCrossQEMU(unittest.TestCase):
    """Compare QEMU core memory with native cores."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(SEGFAULT_CORE) or not os.path.exists(QEMU_CORE):
            raise unittest.SkipTest("Both segfault and QEMU cores required")
        cls.project = angr.Project(CRASHER_BIN)
        cls.native_state = cls.project.factory.core_state(SEGFAULT_CORE)
        cls.qemu_state = cls.project.factory.core_state(QEMU_CORE)

    def test_global_marker_matches_native(self):
        """QEMU and native cores should have the same global_marker value."""
        val_native = self.native_state.solver.eval(
            self.native_state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE")
        )
        val_qemu = self.qemu_state.solver.eval(
            self.qemu_state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE")
        )
        self.assertEqual(val_native, val_qemu)
        self.assertEqual(val_native, GLOBAL_MARKER_VAL)

    def test_text_matches_native(self):
        """QEMU and native cores should have the same .text content."""
        native_byte = self.native_state.solver.eval(
            self.native_state.memory.load(CRASH_ADDR, 1)
        )
        qemu_byte = self.qemu_state.solver.eval(
            self.qemu_state.memory.load(CRASH_ADDR, 1)
        )
        self.assertEqual(native_byte, qemu_byte)


if __name__ == "__main__":
    unittest.main()

"""Tests for angr's core_state() factory method.

These tests verify that core_state() correctly restores register state and memory
from ELF core dump files, using a simple crasher binary that segfaults on a null
pointer dereference.

The crasher binary is compiled from tests/cores/crasher.c at test time:
  - Sets global_marker = 0xBEEF
  - Calls do_crash(NULL) which dereferences NULL, causing SIGSEGV
  - At crash: RIP = 0x4011a6 (inside do_crash), RDI = 0

Core dumps are generated at test time (not committed to git):
  - crasher_segfault.core: Natural segfault core (ulimit -c unlimited)
  - crasher_gdb.core: GDB gcore output
  - crasher_qemu.core: QEMU-user core dump (trimmed to guest-only segments)
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest

import angr


CORES_DIR = os.path.join(os.path.dirname(__file__), "cores")
CRASHER_SRC = os.path.join(CORES_DIR, "crasher.c")
CRASHER_BIN = os.path.join(CORES_DIR, "crasher")
SEGFAULT_CORE = os.path.join(CORES_DIR, "crasher_segfault.core")
GDB_CORE = os.path.join(CORES_DIR, "crasher_gdb.core")
QEMU_CORE = os.path.join(CORES_DIR, "crasher_qemu.core")

# Known values from the crasher binary (deterministic with -no-pie -O0)
CRASH_ADDR = 0x4011A6  # Address of the faulting instruction in do_crash
DO_CRASH_ADDR = 0x401196  # Start of do_crash function
MAIN_ADDR = 0x4011AF  # Start of main function
GLOBAL_MARKER_ADDR = 0x404030  # Address of global_marker variable
GLOBAL_MARKER_VAL = 0xBEEF  # Value set before crash

# Module-level setup error (set if compilation fails)
_setup_error = None


# ---------------------------------------------------------------------------
# Core generation helpers
# ---------------------------------------------------------------------------

# ELF constants for QEMU core trimming
_PT_LOAD = 1
_PT_NOTE = 4
_NT_AUXV = 6
_NT_FILE = 0x46494C45
_NT_X86_XSTATE = 0x202
_GUEST_VADDR_LO = 0x400000
_GUEST_VADDR_HI = 0x500000


def _compile_crasher():
    """Compile crasher.c with deterministic addresses."""
    result = subprocess.run(
        ["gcc", "-g", "-O0", "-no-pie", "-o", CRASHER_BIN, CRASHER_SRC],
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gcc failed: {result.stderr.decode()}")


def _find_core_in(directory):
    """Find a core dump file in the given directory."""
    for name in sorted(os.listdir(directory)):
        if name == "core" or name.startswith("core."):
            return os.path.join(directory, name)
    return None


def _core_pattern_is_file_based():
    """Return True if /proc/sys/kernel/core_pattern writes to a file (not a pipe)."""
    try:
        with open("/proc/sys/kernel/core_pattern") as f:
            return not f.read().strip().startswith("|")
    except OSError:
        return False


def _generate_segfault_core(binary, core_path):
    """Run the binary to crash and collect the resulting core dump."""
    tmpdir = tempfile.mkdtemp(prefix="angr_core_seg_")
    try:
        subprocess.run(
            f"ulimit -c unlimited; exec {binary}",
            shell=True,
            cwd=tmpdir,
            timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        found = _find_core_in(tmpdir)
        if found is None:
            raise RuntimeError("No core dump generated (check /proc/sys/kernel/core_pattern)")
        shutil.move(found, core_path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _generate_gdb_core(binary, core_path):
    """Use GDB to generate a core dump at the crash point."""
    result = subprocess.run(
        [
            "gdb",
            "-batch",
            "-nx",
            "-ex",
            "run",
            "-ex",
            f"gcore {core_path}",
            "-ex",
            "quit",
            binary,
        ],
        capture_output=True,
        timeout=30,
    )
    if not os.path.exists(core_path):
        raise RuntimeError(f"gdb gcore failed: {result.stderr.decode()}")


def _trim_qemu_core(raw_path, out_path):
    """Trim a raw QEMU-user core to guest-only segments.

    Raw QEMU cores are 150+ MB because they include QEMU host memory, JIT cache,
    and host libraries.  This keeps only guest binary LOAD segments (vaddr in the
    0x400000-0x500000 range) and a NOTE segment stripped of NT_AUXV, NT_FILE, and
    NT_X86_XSTATE (which reference host memory or contain sensitive host data).
    """
    with open(raw_path, "rb") as f:
        raw = f.read()

    # ELF64 header fields
    e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", raw, 0x36)[0]
    e_phnum = struct.unpack_from("<H", raw, 0x38)[0]

    # Scan program headers - decide what to keep
    keep = []  # list of (phdr_index, seg_data_override_or_None)
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", raw, base)[0]
        p_vaddr = struct.unpack_from("<Q", raw, base + 0x10)[0]

        if p_type == _PT_NOTE:
            # Filter individual notes inside the NOTE segment
            p_offset = struct.unpack_from("<Q", raw, base + 8)[0]
            p_filesz = struct.unpack_from("<Q", raw, base + 0x20)[0]
            strip = {_NT_AUXV, _NT_FILE, _NT_X86_XSTATE}
            kept_notes = []
            pos, end = p_offset, p_offset + p_filesz
            while pos < end:
                namesz, descsz, ntype = struct.unpack_from("<III", raw, pos)
                total = 12 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3)
                if ntype not in strip:
                    kept_notes.append(raw[pos : pos + total])
                pos += total
            keep.append((i, b"".join(kept_notes)))

        elif p_type == _PT_LOAD and _GUEST_VADDR_LO <= p_vaddr < _GUEST_VADDR_HI:
            keep.append((i, None))  # use original segment data

    # Lay out the trimmed ELF: header -> phdrs -> segment data
    ehdr_sz = 64
    phdr_sz = 56  # sizeof(Elf64_Phdr)
    new_phnum = len(keep)
    data_start = (ehdr_sz + new_phnum * phdr_sz + 7) & ~7

    # Prepare segment blobs and compute file offsets
    offsets = []
    blobs = []
    cur = data_start
    for idx, override in keep:
        base = e_phoff + idx * e_phentsize
        if override is not None:
            blob = override
        else:
            p_offset = struct.unpack_from("<Q", raw, base + 8)[0]
            p_filesz = struct.unpack_from("<Q", raw, base + 0x20)[0]
            blob = raw[p_offset : p_offset + p_filesz]
        offsets.append(cur)
        blobs.append(blob)
        cur = (cur + len(blob) + 7) & ~7

    # Write output
    header = bytearray(raw[:ehdr_sz])
    struct.pack_into("<Q", header, 0x20, ehdr_sz)  # e_phoff right after header
    struct.pack_into("<H", header, 0x38, new_phnum)

    with open(out_path, "wb") as f:
        f.write(header)
        for j, (idx, override) in enumerate(keep):
            base = e_phoff + idx * e_phentsize
            p_type, p_flags = struct.unpack_from("<II", raw, base)
            p_vaddr = struct.unpack_from("<Q", raw, base + 0x10)[0]
            p_paddr = struct.unpack_from("<Q", raw, base + 0x18)[0]
            p_memsz = struct.unpack_from("<Q", raw, base + 0x28)[0]
            p_align = struct.unpack_from("<Q", raw, base + 0x30)[0]
            filesz = len(blobs[j])
            memsz = 0 if override is not None else p_memsz
            f.write(
                struct.pack(
                    "<IIQQQQQQ",
                    p_type,
                    p_flags,
                    offsets[j],
                    p_vaddr,
                    p_paddr,
                    filesz,
                    memsz,
                    p_align,
                )
            )
        # Pad to data_start
        pad = data_start - f.tell()
        if pad > 0:
            f.write(b"\x00" * pad)
        # Write segment data
        for j, blob in enumerate(blobs):
            gap = offsets[j] - f.tell()
            if gap > 0:
                f.write(b"\x00" * gap)
            f.write(blob)


def _generate_qemu_core(binary, core_path):
    """Run the binary under QEMU-user, collect and trim the resulting core."""
    tmpdir = tempfile.mkdtemp(prefix="angr_core_qemu_")
    try:
        subprocess.run(
            f"ulimit -c unlimited; exec qemu-x86_64 {binary}",
            shell=True,
            cwd=tmpdir,
            timeout=30,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        found = _find_core_in(tmpdir)
        if found is None:
            raise RuntimeError("No QEMU core dump generated")
        _trim_qemu_core(found, core_path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Module setup / teardown
# ---------------------------------------------------------------------------

_GENERATED_FILES = [CRASHER_BIN, SEGFAULT_CORE, GDB_CORE, QEMU_CORE]


def setUpModule():
    global _setup_error

    if not shutil.which("gcc"):
        _setup_error = "gcc not available"
        return

    try:
        _compile_crasher()
    except Exception as exc:
        _setup_error = str(exc)
        return

    file_based = _core_pattern_is_file_based()

    if file_based:
        try:
            _generate_segfault_core(CRASHER_BIN, SEGFAULT_CORE)
        except Exception:
            pass

    if shutil.which("gdb"):
        try:
            _generate_gdb_core(CRASHER_BIN, GDB_CORE)
        except Exception:
            pass

    if shutil.which("qemu-x86_64") and file_based:
        try:
            _generate_qemu_core(CRASHER_BIN, QEMU_CORE)
        except Exception:
            pass


def tearDownModule():
    for path in _GENERATED_FILES:
        try:
            os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Skip helper
# ---------------------------------------------------------------------------


def _require(*paths):
    """Raise SkipTest if compilation failed or any required path is missing."""
    if _setup_error:
        raise unittest.SkipTest(_setup_error)
    for p in paths:
        if not os.path.exists(p):
            raise unittest.SkipTest(f"{os.path.basename(p)} not available")


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestCoreStateSegfault(unittest.TestCase):
    """Test core_state() with a natural segfault core dump."""

    @classmethod
    def setUpClass(cls):
        _require(CRASHER_BIN, SEGFAULT_CORE)
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
        _require(CRASHER_BIN, GDB_CORE)
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
        _require(CRASHER_BIN, SEGFAULT_CORE)
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
        _require(CRASHER_BIN, QEMU_CORE)
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
        val = self.state.solver.eval(self.state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE"))
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
        _require(CRASHER_BIN)
        p = angr.Project(CRASHER_BIN)
        with self.assertRaises(angr.errors.AngrError):
            p.factory.core_state(CRASHER_BIN)


class TestCoreStateCrossCore(unittest.TestCase):
    """Cross-core-type comparisons to verify consistency."""

    @classmethod
    def setUpClass(cls):
        _require(CRASHER_BIN, SEGFAULT_CORE, GDB_CORE)
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
        val_gdb = self.gdb_state.solver.eval(self.gdb_state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE"))
        self.assertEqual(val_seg, val_gdb)
        self.assertEqual(val_seg, GLOBAL_MARKER_VAL)


class TestCoreStateCrossQEMU(unittest.TestCase):
    """Compare QEMU core memory with native cores."""

    @classmethod
    def setUpClass(cls):
        _require(CRASHER_BIN, SEGFAULT_CORE, QEMU_CORE)
        cls.project = angr.Project(CRASHER_BIN)
        cls.native_state = cls.project.factory.core_state(SEGFAULT_CORE)
        cls.qemu_state = cls.project.factory.core_state(QEMU_CORE)

    def test_global_marker_matches_native(self):
        """QEMU and native cores should have the same global_marker value."""
        val_native = self.native_state.solver.eval(
            self.native_state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE")
        )
        val_qemu = self.qemu_state.solver.eval(self.qemu_state.memory.load(GLOBAL_MARKER_ADDR, 4, endness="Iend_LE"))
        self.assertEqual(val_native, val_qemu)
        self.assertEqual(val_native, GLOBAL_MARKER_VAL)

    def test_text_matches_native(self):
        """QEMU and native cores should have the same .text content."""
        native_byte = self.native_state.solver.eval(self.native_state.memory.load(CRASH_ADDR, 1))
        qemu_byte = self.qemu_state.solver.eval(self.qemu_state.memory.load(CRASH_ADDR, 1))
        self.assertEqual(native_byte, qemu_byte)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import os.path
import struct
import tempfile

import angr
from angr.procedures.glibc.__libc_start_main import (
    __libc_start_main as _libc_start_main,
)
from angr.rustylib.fuzzer import (
    DeterministicMutator,
    Fuzzer,
    HavocMutator,
    InMemoryCorpus,
    OnDiskCorpus,
)
from tests.common import bin_location

# pylint: disable=missing-class-docstring,no-self-use

SHELLCODE = """
cmp al, 0x41
je path_a
cmp al, 0x42
je path_b
ret
path_a:
nop
ret
path_b:
nop
nop
ret
"""

# Shellcode with a crash path: 0x43 triggers an access to unmapped memory
SHELLCODE_WITH_CRASH = """
cmp al, 0x43
je crash_path
cmp al, 0x41
je path_a
ret
path_a:
nop
ret
crash_path:
mov rdi, 0xdeadbeef
mov byte ptr [rdi], 0
ret
"""

# Shellcode with a TLS access: fs:[0x10000] is unmapped when FS_OFFSET=0
SHELLCODE_TLS_ACCESS = """
mov rax, qword ptr fs:[0x10000]
ret
"""

RETURN_ADDR = 0x100


def _apply_fn(state: angr.SimState, input: bytes):  # pylint: disable=redefined-builtin
    # Feed the fuzzed byte into rax so the binary can branch on it.
    state.regs.rax = input[0] if input else 0
    # Set the return address so the executor's breakpoint fires on normal return.
    # Must be inside the binary's mapped region but past the shellcode bytes.
    cc = state.project.factory.cc()
    cc.return_addr.set_value(state, RETURN_ADDR)


class TestFuzzer:
    def test_fuzzer(self):
        project = angr.load_shellcode(SHELLCODE, "amd64")
        base_state = project.factory.entry_state()
        corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C"])
        solutions = InMemoryCorpus()

        fuzzer = Fuzzer(base_state, corpus, solutions, _apply_fn, 0, 0, max_mutations=2)

        new_corpus_entry = fuzzer.run_once()
        live_corpus = fuzzer.corpus()
        assert isinstance(live_corpus, InMemoryCorpus)
        assert 0 <= new_corpus_entry < len(live_corpus)

    def test_fuzzer_ondisk(self):
        project = angr.load_shellcode(SHELLCODE, "amd64")
        base_state = project.factory.entry_state()

        with tempfile.TemporaryDirectory() as tmp_path:
            corpus_dir = os.path.join(tmp_path, "corpus")
            os.makedirs(corpus_dir)
            corpus = OnDiskCorpus(corpus_dir)
            for seed in [b"\x00", b"A", b"B", b"C"]:
                corpus.add(seed)
            solutions_dir = os.path.join(tmp_path, "solutions")
            os.makedirs(solutions_dir)
            solutions = OnDiskCorpus(solutions_dir)

            fuzzer = Fuzzer(base_state, corpus, solutions, _apply_fn, 0, 0, max_mutations=2)

            new_corpus_entry = fuzzer.run_once()
            live_corpus = fuzzer.corpus()
            assert isinstance(live_corpus, OnDiskCorpus)
            assert 0 <= new_corpus_entry < len(live_corpus)
            live_solutions = fuzzer.solutions()
            assert isinstance(live_solutions, OnDiskCorpus)

    def test_fuzzer_mixed_inmem_corpus_ondisk_solutions(self):
        project = angr.load_shellcode(SHELLCODE, "amd64")
        base_state = project.factory.entry_state()

        with tempfile.TemporaryDirectory() as tmp_path:
            corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C"])
            solutions_dir = os.path.join(tmp_path, "solutions_mixed1")
            os.makedirs(solutions_dir)
            solutions = OnDiskCorpus(solutions_dir)

            fuzzer = Fuzzer(base_state, corpus, solutions, _apply_fn, 0, 0, max_mutations=2)
            new_corpus_entry = fuzzer.run_once()
            live_corpus = fuzzer.corpus()
            assert isinstance(live_corpus, InMemoryCorpus)
            assert 0 <= new_corpus_entry < len(live_corpus)
            live_solutions = fuzzer.solutions()
            assert isinstance(live_solutions, OnDiskCorpus)

    def test_fuzzer_mixed_ondisk_corpus_inmem_solutions(self):
        project = angr.load_shellcode(SHELLCODE, "amd64")
        base_state = project.factory.entry_state()

        with tempfile.TemporaryDirectory() as tmp_path:
            corpus_dir = os.path.join(tmp_path, "corpus_mixed2")
            os.makedirs(corpus_dir)
            corpus = OnDiskCorpus(corpus_dir)
            for seed in [b"\x00", b"A", b"B", b"C"]:
                corpus.add(seed)
            solutions = InMemoryCorpus()

            fuzzer = Fuzzer(base_state, corpus, solutions, _apply_fn, 0, 0, max_mutations=2)
            new_corpus_entry = fuzzer.run_once()
            live_corpus = fuzzer.corpus()
            assert isinstance(live_corpus, OnDiskCorpus)
            assert 0 <= new_corpus_entry < len(live_corpus)
            live_solutions = fuzzer.solutions()
            assert isinstance(live_solutions, InMemoryCorpus)

    def test_havoc_mutator_config(self):
        """Test that HavocMutator with configuration options works."""
        project = angr.load_shellcode(SHELLCODE, "amd64")
        base_state = project.factory.entry_state()
        corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C"])
        solutions = InMemoryCorpus()

        mutator = HavocMutator(max_stack_pow=2)
        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_fn,
            0,
            0,
            max_mutations=2,
            mutator=mutator,
        )

        new_corpus_entry = fuzzer.run_once()
        live_corpus = fuzzer.corpus()
        assert isinstance(live_corpus, InMemoryCorpus)
        assert 0 <= new_corpus_entry < len(live_corpus)

    def test_deterministic_mutator_finds_solution(self):
        """Test that a deterministic mutator producing a crash value yields a solution."""
        project = angr.load_shellcode(SHELLCODE_WITH_CRASH, "amd64")
        base_state = project.factory.entry_state()

        corpus = InMemoryCorpus.from_list([b"\x00"])
        solutions = InMemoryCorpus()

        # The deterministic mutator will produce 0x43 ('C') which triggers the crash path
        mutator = DeterministicMutator([b"\x43"])
        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_fn,
            0,
            0,
            max_mutations=1,
            mutator=mutator,
        )

        fuzzer.run_once()
        live_solutions = fuzzer.solutions()
        assert len(live_solutions) >= 1, "Expected at least one solution from crash path"

    def test_deterministic_mutator_no_crash(self):
        """Test that a deterministic mutator with non-crash values does not produce solutions."""
        project = angr.load_shellcode(SHELLCODE_WITH_CRASH, "amd64")
        base_state = project.factory.entry_state()

        corpus = InMemoryCorpus.from_list([b"\x00"])
        solutions = InMemoryCorpus()

        # Only produce values that do NOT trigger the crash path
        mutator = DeterministicMutator([b"\x41"])
        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_fn,
            0,
            0,
            max_mutations=1,
            mutator=mutator,
        )

        fuzzer.run_once()
        live_solutions = fuzzer.solutions()
        assert len(live_solutions) == 0, "path_a should not crash"

    def test_deterministic_mutator_sequence(self):
        """Test that a deterministic mutator cycles through its sequence and finds solutions."""
        project = angr.load_shellcode(SHELLCODE_WITH_CRASH, "amd64")
        base_state = project.factory.entry_state()

        corpus = InMemoryCorpus.from_list([b"\x00"])
        solutions = InMemoryCorpus()

        # Cycle: first produces 0x41 (path_a, no crash), then 0x43 (crash_path)
        mutator = DeterministicMutator([b"\x41", b"\x43"])
        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_fn,
            0,
            0,
            max_mutations=1,
            mutator=mutator,
        )

        # First iteration: mutator produces 0x41 -> path_a -> no crash
        fuzzer.run_once()
        solutions_after_first = fuzzer.solutions()
        assert len(solutions_after_first) == 0, "path_a should not crash"

        # Second iteration: mutator produces 0x43 -> crash_path -> solution
        fuzzer.run_once()
        solutions_after_second = fuzzer.solutions()
        assert len(solutions_after_second) >= 1, "crash_path should produce a solution"

    def test_tls_emulation_gap_not_crash(self):
        """TLS access via uninitialised FS_OFFSET should be an emulation gap, not a crash."""
        # With FS_OFFSET=0 the effective address 0x10000 is unmapped, triggering
        # ReadUnmapped.  The emulation-gap heuristic should recognise the fs:
        # prefix and classify this as Ijk_EmFail, NOT Ijk_SigSEGV.
        project = angr.load_shellcode(SHELLCODE_TLS_ACCESS, "amd64")
        base_state = project.factory.entry_state()

        corpus = InMemoryCorpus.from_list([b"\x00"])
        solutions = InMemoryCorpus()

        mutator = DeterministicMutator([b"\x00"])
        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_fn,
            0,
            0,
            max_mutations=1,
            mutator=mutator,
        )

        fuzzer.run_once()
        live_solutions = fuzzer.solutions()
        assert len(live_solutions) == 0, "TLS emulation gap should not be classified as a crash"

    def test_concrete_libc_start_main_hook(self):
        """__libc_start_main hook redirects to main through the fuzzer."""

        class _Hook(angr.SimProcedure):
            NO_RET = True

            def run(self, main, argc, argv, init, fini):
                main, argc, argv, _, _ = _libc_start_main._extract_args(
                    self.state, main, argc, argv, init, fini
                )
                self.state.regs.rdi = argc
                self.state.regs.rsi = argv
                envp = argv + (argc + 1) * self.state.arch.bytes
                self.state.regs.rdx = envp
                self.jump(main)

        # Reuse SHELLCODE as "main" — it branches on al
        project = angr.load_shellcode(SHELLCODE, "amd64")

        # Hook an address within the mapped page as __libc_start_main
        HOOK_ADDR = 0x200
        project.hook(HOOK_ADDR, _Hook())

        # Start at the hook; rdi = main (shellcode at 0x0)
        base_state = project.factory.blank_state(addr=HOOK_ADDR)
        base_state.regs.rdi = 0
        base_state.regs.rsi = 1
        base_state.regs.rdx = 0

        corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C"])
        solutions = InMemoryCorpus()

        fuzzer = Fuzzer(base_state, corpus, solutions, _apply_fn, 0, 0, max_mutations=2)

        new_corpus_entry = fuzzer.run_once()
        live_corpus = fuzzer.corpus()
        assert isinstance(live_corpus, InMemoryCorpus)
        assert 0 <= new_corpus_entry < len(live_corpus)

    def test_vuln_stacksmash_deterministic(self):
        """Test that DeterministicMutator detects a stack buffer overflow in a real binary.

        vuln_stacksmash has main():
            sub rsp, 0x70        // 112-byte buffer
            read(0, buf, 0x800)  // reads up to 2048 bytes into 112-byte buffer
            leave; ret

        We start execution after the read() call and write fuzzed bytes directly
        into the buffer.  Inputs longer than 120 bytes overwrite the return
        address, causing MEMORY_ERROR on ret → CrashFeedback → solution.
        """
        bin_path = os.path.join(bin_location, "tests", "x86_64", "vuln_stacksmash")
        project = angr.Project(bin_path, auto_load_libs=False)

        AFTER_READ = 0x400505  # mov eax, 0 (instruction after call read@plt)
        STACK_RET = 0x400100  # breakpoint address, within binary's mapped region

        # Allocate and fully materialise a stack page so icicle can sync it.
        # (concrete_load returns empty for sparse pages, causing lost writes.)
        STACK_PAGE = 0x651000
        base_state = project.factory.blank_state(
            addr=AFTER_READ,
            add_options={
                angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        base_state.memory.map_region(STACK_PAGE, 0x1000, 7)  # rwx
        base_state.memory.store(STACK_PAGE, b"\x00" * 0x1000)  # materialise

        # Set up the stack frame as if main's prologue already ran:
        #   push rbp; mov rbp, rsp; sub rsp, 0x70
        RBP = STACK_PAGE + 0xFF0  # near top of page
        RSP = RBP - 0x70

        base_state.regs.rbp = RBP
        base_state.regs.rsp = RSP

        def stacksmash_apply_fn(state: angr.SimState, input_bytes: bytes):
            # Reset the saved rbp and return address each iteration
            state.memory.store(RBP, struct.pack("<Q", 0))  # saved rbp
            state.memory.store(RBP + 8, struct.pack("<Q", STACK_RET))  # return addr
            # Write fuzzed input into the buffer at [rbp - 0x70].
            # >120 bytes overflows past saved rbp (8) into the return address.
            state.memory.store(RBP - 0x70, input_bytes)
            # Tell the executor where to set its breakpoint
            cc = state.project.factory.cc()
            cc.return_addr.set_value(state, STACK_RET)

        corpus = InMemoryCorpus.from_list([b"\x00"])
        solutions = InMemoryCorpus()

        # 128 bytes of 'A': overwrites buffer (112) + saved rbp (8) + return addr (8)
        crash_input = b"A" * 128
        mutator = DeterministicMutator([crash_input])
        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            stacksmash_apply_fn,
            0,
            0,
            max_mutations=1,
            mutator=mutator,
        )

        fuzzer.run_once()
        live_solutions = fuzzer.solutions()
        assert len(live_solutions) >= 1, "Stack buffer overflow should produce a solution"

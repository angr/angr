from __future__ import annotations

import os.path
import tempfile

import angr
from angr.rustylib.fuzzer import Fuzzer, InMemoryCorpus, OnDiskCorpus

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


def _apply_fn(state: angr.SimState, input: bytes):  # pylint: disable=redefined-builtin
    # Feed the fuzzed byte into rax so the binary can branch on it.
    state.regs.rax = input[0] if input else 0
    # Set the return address to the entry so the breakpoint is at a mapped addr.
    cc = state.project.factory.cc()
    cc.return_addr.set_value(state, state.project.entry)


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

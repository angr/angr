from __future__ import annotations

import os.path

import angr
from angr.rustylib.fuzzer import Fuzzer, InMemoryCorpus, OnDiskCorpus

from tests.common import bin_location


def test_fuzzer():
    project = angr.Project(
        os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=True, use_sim_procedures=False
    )
    stdin = angr.SimFile(content=b"", concrete=True)
    base_state = project.factory.entry_state(stdin=stdin, add_options={angr.options.STRICT_PAGE_ACCESS})

    def apply_fn(state: angr.SimState, input: bytes):  # pylint: disable=redefined-builtin
        print("Apply function called with input:", input, flush=True)
        state.project.factory.cc().return_addr.set_value(state, 0xDEADBEEF)
        state.posix.stdin.write(0, "usernameN")
        state.posix.stdin.write(0, input)
        print("Done")

    corpus = InMemoryCorpus.from_list([b"S", b"SO", b"SOS", b"SOSN"])
    solutions = InMemoryCorpus()

    fuzzer = Fuzzer(base_state, corpus, solutions, apply_fn, 0, 0)

    new_corpus_entry = fuzzer.run_once()
    print("New corpus entry:", new_corpus_entry, flush=True)
    live_corpus = fuzzer.corpus()
    assert isinstance(live_corpus, InMemoryCorpus)
    assert 0 <= new_corpus_entry < len(live_corpus)
    print("Value: ", live_corpus[new_corpus_entry], flush=True)
    print("Fuzzer run completed", flush=True)

    new_corpus_entry = fuzzer.run_once()
    print("New corpus entry:", new_corpus_entry, flush=True)
    live_corpus = fuzzer.corpus()
    assert isinstance(live_corpus, InMemoryCorpus)
    assert 0 <= new_corpus_entry < len(live_corpus)
    print("Value: ", live_corpus[new_corpus_entry], flush=True)
    print("Fuzzer run completed", flush=True)


def test_fuzzer_ondisk(tmp_path):
    print("Running test: ondisk", flush=True)
    project = angr.Project(
        os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=True, use_sim_procedures=False
    )
    stdin = angr.SimFile(content=b"", concrete=True)
    base_state = project.factory.entry_state(stdin=stdin, add_options={angr.options.STRICT_PAGE_ACCESS})

    def apply_fn(state: angr.SimState, input: bytes):  # pylint: disable=redefined-builtin
        print("Apply function called with input:", input, flush=True)
        state.project.factory.cc().return_addr.set_value(state, 0xDEADBEEF)
        state.posix.stdin.write(0, "usernameN")
        state.posix.stdin.write(0, input)
        print("Done")

    corpus_dir = str(tmp_path / "corpus")
    os.makedirs(corpus_dir, exist_ok=True)
    corpus = OnDiskCorpus(corpus_dir)
    for seed in [b"S", b"SO", b"SOS", b"SOSN"]:
        corpus.add(seed)
    solutions_dir = str(tmp_path / "solutions")
    os.makedirs(solutions_dir, exist_ok=True)
    solutions = OnDiskCorpus(solutions_dir)

    fuzzer = Fuzzer(base_state, corpus, solutions, apply_fn, 0, 0)

    new_corpus_entry = fuzzer.run_once()
    print("New corpus entry:", new_corpus_entry, flush=True)
    live_corpus = fuzzer.corpus()
    assert isinstance(live_corpus, OnDiskCorpus)
    assert 0 <= new_corpus_entry < len(live_corpus)
    print("Value: ", live_corpus[new_corpus_entry], flush=True)
    print("Fuzzer run completed", flush=True)
    live_solutions = fuzzer.solutions()
    assert isinstance(live_solutions, OnDiskCorpus)


def test_fuzzer_mixed_inmem_corpus_ondisk_solutions(tmp_path):
    print("Running test: mixed_inmem_corpus_ondisk_solutions", flush=True)
    project = angr.Project(
        os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=True, use_sim_procedures=False
    )
    stdin = angr.SimFile(content=b"", concrete=True)
    base_state = project.factory.entry_state(stdin=stdin, add_options={angr.options.STRICT_PAGE_ACCESS})

    def apply_fn(state: angr.SimState, input: bytes):  # pylint: disable=redefined-builtin
        print("Apply function called with input:", input, flush=True)
        state.project.factory.cc().return_addr.set_value(state, 0xDEADBEEF)
        state.posix.stdin.write(0, "usernameN")
        state.posix.stdin.write(0, input)
        print("Done")

    corpus = InMemoryCorpus.from_list([b"S", b"SO", b"SOS", b"SOSN"])
    solutions_dir = str(tmp_path / "solutions_mixed1")
    os.makedirs(solutions_dir, exist_ok=True)
    solutions = OnDiskCorpus(solutions_dir)

    fuzzer = Fuzzer(base_state, corpus, solutions, apply_fn, 0, 0)
    new_corpus_entry = fuzzer.run_once()
    print("New corpus entry:", new_corpus_entry, flush=True)
    live_corpus = fuzzer.corpus()
    assert isinstance(live_corpus, InMemoryCorpus)
    assert 0 <= new_corpus_entry < len(live_corpus)
    print("Value: ", live_corpus[new_corpus_entry], flush=True)
    print("Fuzzer run completed", flush=True)
    live_solutions = fuzzer.solutions()
    assert isinstance(live_solutions, OnDiskCorpus)


def test_fuzzer_mixed_ondisk_corpus_inmem_solutions(tmp_path):
    print("Running test: mixed_ondisk_corpus_inmem_solutions", flush=True)
    project = angr.Project(
        os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=True, use_sim_procedures=False
    )
    stdin = angr.SimFile(content=b"", concrete=True)
    base_state = project.factory.entry_state(stdin=stdin, add_options={angr.options.STRICT_PAGE_ACCESS})

    def apply_fn(state: angr.SimState, input: bytes):  # pylint: disable=redefined-builtin
        print("Apply function called with input:", input, flush=True)
        state.project.factory.cc().return_addr.set_value(state, 0xDEADBEEF)
        state.posix.stdin.write(0, "usernameN")
        state.posix.stdin.write(0, input)
        print("Done")

    corpus_dir = str(tmp_path / "corpus_mixed2")
    os.makedirs(corpus_dir, exist_ok=True)
    corpus = OnDiskCorpus(corpus_dir)
    for seed in [b"S", b"SO", b"SOS", b"SOSN"]:
        corpus.add(seed)
    solutions = InMemoryCorpus()

    fuzzer = Fuzzer(base_state, corpus, solutions, apply_fn, 0, 0)
    new_corpus_entry = fuzzer.run_once()
    print("New corpus entry:", new_corpus_entry, flush=True)
    live_corpus = fuzzer.corpus()
    assert isinstance(live_corpus, OnDiskCorpus)
    assert 0 <= new_corpus_entry < len(live_corpus)
    print("Value: ", live_corpus[new_corpus_entry], flush=True)
    print("Fuzzer run completed", flush=True)
    live_solutions = fuzzer.solutions()
    assert isinstance(live_solutions, InMemoryCorpus)

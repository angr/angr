from __future__ import annotations

import os.path

import angr
from angr.rustylib.fuzzer import Fuzzer, InMemoryCorpus

from tests.common import bin_location


def test_fuzzer():
    project = angr.Project(
        os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=True, use_sim_procedures=False
    )
    stdin = angr.SimFile(content=b"", concrete=True)
    base_state = project.factory.entry_state(stdin=stdin, add_options={angr.options.STRICT_PAGE_ACCESS})

    def apply_fn(state: angr.SimState, input: bytes):  # pylint: disable=redefined-builtin
        print("Apply function called with input:", input, flush=True)
        state.posix.stdin.write(0, input)
        print("Done")

    corpus = InMemoryCorpus.from_list([b"S"])
    solutions = InMemoryCorpus()

    fuzzer = Fuzzer(base_state, corpus, solutions, apply_fn, 0, 0)

    new_corpus_entry = fuzzer.run_once()
    print("New corpus entry:", new_corpus_entry, flush=True)
    print("Value: ", corpus[new_corpus_entry], flush=True)
    print("Fuzzer run completed", flush=True)

    new_corpus_entry = fuzzer.run_once()
    print("New corpus entry:", new_corpus_entry, flush=True)
    print("Value: ", corpus[new_corpus_entry], flush=True)
    print("Fuzzer run completed", flush=True)

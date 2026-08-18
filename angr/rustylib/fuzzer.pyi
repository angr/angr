from collections.abc import Callable
from datetime import timedelta
from typing import Self

from angr.sim_state import SimState

class InMemoryCorpus:
    def __new__(cls) -> Self: ...
    @staticmethod
    def from_list(inputs: list[bytes]) -> InMemoryCorpus: ...
    def to_bytes_list(self) -> list[bytes]: ...
    def __getitem__(self, idx: int) -> bytes: ...
    def __len__(self) -> int: ...

class OnDiskCorpus:
    def __new__(cls, dir_path: str) -> Self: ...
    def add(self, input: bytes) -> int: ...
    def to_bytes_list(self) -> list[bytes]: ...
    def __getitem__(self, idx: int) -> bytes: ...
    def __len__(self) -> int: ...

class ClientStats:
    @property
    def enabled(self) -> bool: ...
    @property
    def corpus_size(self) -> int: ...
    @property
    def last_corpus_time(self) -> timedelta: ...
    @property
    def executions(self) -> int: ...
    @property
    def prev_state_executions(self) -> int: ...
    @property
    def objective_size(self) -> int: ...
    @property
    def last_objective_time(self) -> timedelta: ...
    @property
    def last_window_time(self) -> timedelta: ...
    @property
    def start_time(self) -> timedelta: ...
    @property
    def execs_per_sec(self) -> float: ...
    @property
    def execs_per_sec_pretty(self) -> str: ...
    @property
    def edges_hit(self) -> int | None: ...
    @property
    def edges_total(self) -> int | None: ...

class HavocMutator:
    def __init__(self, max_stack_pow: int | None = None):
        """
        Configuration for the standard Havoc mutator.

        :param max_stack_pow: Maximum power of 2 for the number of stacked mutations per iteration.
            Defaults to 7 (up to 128 stacked mutations). Lower values produce less aggressive mutations.
        """

class DeterministicMutator:
    def __init__(self, values: list[bytes]):
        """
        A mutator that cycles through a fixed sequence of values instead of random mutations.
        Useful for writing tests with predictable mutation outputs.

        :param values: Non-empty list of byte values to cycle through.
        """

class Fuzzer:
    def __init__(
        self,
        base_state: SimState,
        corpus: InMemoryCorpus | OnDiskCorpus,
        solutions: InMemoryCorpus | OnDiskCorpus,
        apply_fn: Callable[[SimState, bytes], None],
        timeout: int = 0,
        seed: int | None = None,
        max_mutations: int | None = None,
        mutator: HavocMutator | DeterministicMutator | None = None,
    ):
        """
        Initialize the fuzzer with the given parameters.
        """

    def corpus(self) -> InMemoryCorpus | OnDiskCorpus: ...
    def solutions(self) -> InMemoryCorpus | OnDiskCorpus: ...
    def run_once(self, progress_callback: Callable[[ClientStats, str, int], None] | None = None) -> int:
        """
        Run the fuzzer for one iteration.

        :raises RuntimeError: If ``progress_callback`` raises.
        """

    def run(
        self, progress_callback: Callable[[ClientStats, str, int], None] | None = None, iterations: int | None = None
    ) -> None:
        """
        Run the fuzzer in a loop or for a set number of iterations.

        :raises RuntimeError: If ``progress_callback`` raises.
        """

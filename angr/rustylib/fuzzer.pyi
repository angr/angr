from collections.abc import Callable
from datetime import timedelta

from angr.sim_state import SimState

class InMemoryCorpus:
    def __new__(cls) -> InMemoryCorpus:
        pass

    @staticmethod
    def from_list(inputs: list[bytes]) -> InMemoryCorpus:
        pass

    def to_bytes_list(self) -> list[bytes]:
        pass

    def __getitem__(self, idx: int) -> bytes:
        pass

    def __len__(self) -> int:
        pass

class ClientStats:
    @property
    def enabled(self) -> bool:
        pass

    @property
    def corpus_size(self) -> int:
        pass

    @property
    def last_corpus_time(self) -> timedelta:
        pass

    @property
    def executions(self) -> int:
        pass

    @property
    def prev_state_executions(self) -> int:
        pass

    @property
    def objective_size(self) -> int:
        pass

    @property
    def last_objective_time(self) -> timedelta:
        pass

    @property
    def last_window_time(self) -> timedelta:
        pass

    @property
    def start_time(self) -> timedelta:
        pass

    @property
    def execs_per_sec(self) -> float:
        pass

    @property
    def execs_per_sec_pretty(self) -> str:
        pass

    @property
    def edges_hit(self) -> int | None:
        pass

    @property
    def edges_total(self) -> int | None:
        pass

class Fuzzer:
    def __init__(
        self,
        state: SimState,
        corpus: InMemoryCorpus,
        solutions: InMemoryCorpus,
        apply_fn: Callable[[SimState, bytes], None],
        timeout: int = 0,
        seed: int | None = None,
    ):
        """
        Initialize the fuzzer with the given parameters.
        """

    def run_once(self, progress_callback: Callable[ClientStats, str, int]) -> int:
        """
        Run the fuzzer for one iteration.
        """

    def run(self, progress_callback: Callable[[ClientStats, str, int], None], iterations: int | None) -> None:
        """
        Run the fuzzer in a loop or for a set number of iterations.
        """

from collections.abc import Callable

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

class Monitor:
    pass

class NopMonitor(Monitor):
    pass

class StderrMonitor(Monitor):
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

    def run_once(self) -> None:
        """
        Run the fuzzer for one iteration.
        """

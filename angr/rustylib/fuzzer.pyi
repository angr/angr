from collections.abc import Callable

from angr.sim_state import SimState

class InMemoryCorpus:
    @staticmethod
    def from_list(inputs: list[bytes]) -> InMemoryCorpus:
        pass

class Fuzzer:
    def __init__(
        self,
        state: SimState,
        corpus: Corpus,
        solutions: Corpus,
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

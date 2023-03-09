from . import SimConcretizationStrategy
import logging


class SimConcretizationStrategyLogging(SimConcretizationStrategy):
    def __init__(self, strategy: SimConcretizationStrategy, is_read: bool):
        super().__init__()
        self._strategy = strategy
        self._is_read = is_read

    def _concretize(self, memory, addr, **kwargs):
        answers = self._strategy._concretize(memory, addr, **kwargs)
        if answers is not None:
            if self._is_read:
                logging.debug(
                    f"Read strategy {type(self._strategy).__name__} on {addr} gave [{', '.join(map(hex, answers))}]"
                )
            else:
                logging.debug(
                    f"Write strategy {type(self._strategy).__name__} on {addr} gave [{', '.join(map(hex, answers))}]"
                )
        return answers

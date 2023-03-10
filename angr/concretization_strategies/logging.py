import logging
from . import SimConcretizationStrategy


class SimConcretizationStrategyLogging(SimConcretizationStrategy):
    """
    Concretization strategy that logs concretization results from another strategy.
    """

    def __init__(self, strategy: SimConcretizationStrategy, is_read_strategy: bool):
        super().__init__()
        self._strategy = strategy
        self._is_read_strategy = is_read_strategy

    def _concretize(self, memory, addr, **kwargs):
        answers = self._strategy._concretize(memory, addr, **kwargs)
        if answers is not None:
            if self._is_read_strategy:
                logging.debug(
                    "Read strategy %s on %s gave [%s]",
                    type(self._strategy).__name__,
                    addr,
                    ", ".join([hex(answer) for answer in answers]),
                )
            else:
                logging.debug(
                    "Write strategy %s on %s gave [%s]",
                    type(self._strategy).__name__,
                    addr,
                    ", ".join([hex(answer) for answer in answers]),
                )
        return answers

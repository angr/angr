from __future__ import annotations

import angr


class _StatefulStrategy(angr.concretization_strategies.SimConcretizationStrategy):
    def __init__(self, values=None):
        super().__init__()
        self.values = [] if values is None else values

    def _concretize(self, memory, addr, **kwargs):
        return None

    def copy(self):
        return _StatefulStrategy(list(self.values))


def test_stateful_concretization_strategies_are_copied_with_memory():
    state = angr.SimState(arch="AMD64")
    strategy = _StatefulStrategy([1])
    state.memory.read_strategies = [strategy, strategy]
    state.memory.write_strategies = [strategy]

    fork = state.copy()
    fork_strategy = fork.memory.read_strategies[0]

    assert fork_strategy is not strategy
    assert fork.memory.read_strategies[1] is fork_strategy
    assert fork.memory.write_strategies[0] is fork_strategy

    fork_strategy.values.append(2)
    assert strategy.values == [1]
    assert fork_strategy.values == [1, 2]

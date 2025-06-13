from __future__ import annotations

import logging
import typing
from abc import abstractmethod, ABCMeta
from typing_extensions import override

import claripy
from angr.engines.successors import SimSuccessors, SuccessorsEngine
from angr.sim_state import SimState

log = logging.getLogger(__name__)


HeavyConcreteState = SimState[int, int]


class ConcreteEngine(SuccessorsEngine, metaclass=ABCMeta):
    """
    ConcreteEngine extends SuccessorsEngine and adds APIs for managing breakpoints.
    """

    @abstractmethod
    def get_breakpoints(self) -> set[int]:
        """Return the set of currently set breakpoints."""

    @abstractmethod
    def add_breakpoint(self, addr: int) -> None:
        """Add a breakpoint at the given address."""

    @abstractmethod
    def remove_breakpoint(self, addr: int) -> None:
        """Remove a breakpoint at the given address, if present."""

    @abstractmethod
    def process_concrete(self, state: HeavyConcreteState, num_inst: int | None = None) -> HeavyConcreteState:
        """
        Process the concrete state and return a HeavyState object.

        :param state: The concrete state to process.
        :return: A HeavyState object representing the processed state.
        """

    @override
    def process_successors(
        self, successors: SimSuccessors, *, num_inst: int | None = None, **kwargs: dict[str, typing.Any]
    ):
        if len(kwargs) > 0:
            log.warning("ConcreteEngine.process_successors received unknown kwargs: %s", kwargs)

        # TODO: Properly error here when the state is not a HeavyConcreteState
        # Alternatively, we could make SimSuccessors generic over the state type too
        concrete_state = typing.cast(HeavyConcreteState, self.state)

        concrete_successor = self.process_concrete(concrete_state, num_inst=num_inst)
        successors.add_successor(
            concrete_successor,
            concrete_successor.ip,
            claripy.true(),
            concrete_successor.history.jumpkind,
            add_guard=False,
        )
        successors.processed = True


__all__ = ["ConcreteEngine", "HeavyConcreteState"]

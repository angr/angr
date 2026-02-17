from __future__ import annotations

import logging
import typing
from abc import abstractmethod, ABCMeta
from collections.abc import Iterable
from typing_extensions import override

import claripy
from angr.engines.successors import SimSuccessors, SuccessorsEngine
from angr.sim_state import SimState

log = logging.getLogger(__name__)


HeavyConcreteState = SimState[int, int]


class ConcreteEngine(SuccessorsEngine, metaclass=ABCMeta):
    """
    ConcreteEngine extends SuccessorsEngine for concrete execution.
    """

    @abstractmethod
    def process_concrete(
        self,
        state: HeavyConcreteState,
        num_inst: int | None = None,
        extra_stop_points: set[int] | None = None,
    ) -> HeavyConcreteState:
        """
        Process the concrete state and return a HeavyState object.

        :param state: The concrete state to process.
        :param num_inst: The maximum number of instructions to execute.
        :param extra_stop_points: A set of additional addresses to stop at.
        :return: A HeavyState object representing the processed state.
        """

    @override
    def process_successors(self, successors: SimSuccessors, *, num_inst: int | None = None, **kwargs: typing.Any):
        extra_stop_points_arg = kwargs.pop("extra_stop_points", None)
        extra_stop_points: set[int] | None = None
        if extra_stop_points_arg is not None:
            extra_stop_points = set(typing.cast(Iterable[int], extra_stop_points_arg))

        if len(kwargs) > 0:
            log.warning("ConcreteEngine.process_successors received unknown kwargs: %s", kwargs)

        # TODO: Properly error here when the state is not a HeavyConcreteState
        # Alternatively, we could make SimSuccessors generic over the state type too
        concrete_state = typing.cast(HeavyConcreteState, self.state)

        concrete_successor = self.process_concrete(
            concrete_state, num_inst=num_inst, extra_stop_points=extra_stop_points
        )
        successors.add_successor(
            concrete_successor,
            concrete_successor.ip,
            claripy.true(),
            concrete_successor.history.jumpkind,
            add_guard=False,
        )
        successors.processed = True


__all__ = ["ConcreteEngine", "HeavyConcreteState"]

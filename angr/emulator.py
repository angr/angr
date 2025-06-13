from __future__ import annotations

import logging
from enum import Enum

from angr.engines.concrete import ConcreteEngine, HeavyConcreteState
from angr.errors import AngrError


log = logging.getLogger(name=__name__)


class EmulatorException(AngrError):
    """Base class for exceptions raised by the Emulator."""


class EngineException(EmulatorException):
    """Exception raised when the emulator encounters an unhandlable error in the engine."""


class StateDivergedException(EmulatorException):
    """Exception raised when an engine returns multiple successors."""


class EmulatorStopReason(Enum):
    """
    Enum representing the reason for stopping the emulator.
    """

    INSTRUCTION_LIMIT = "instruction_limit"
    BREAKPOINT = "breakpoint"
    NO_SUCCESSORS = "no_successors"
    MEMORY_ERROR = "memory_error"
    FAILURE = "failure"
    EXIT = "exit"


class Emulator:
    """
    Emulator is a utility that adapts an angr `ConcreteEngine` to a more
    user-friendly interface for concrete execution. It only supports concrete
    execution and requires a ConcreteEngine.

    Saftey: This class is not thread-safe. It should only be used in a
    single-threaded context. It can be safely shared between multiple threads,
    provided that only one thread is using it at a time.
    """

    _engine: ConcreteEngine
    _state: HeavyConcreteState

    def __init__(self, engine: ConcreteEngine, init_state: HeavyConcreteState):
        """
        :param engine: The `ConcreteEngine` to use for emulation.
        :param init_state: The initial state to use for emulation.
        """
        self._engine = engine
        self._state = init_state

    @property
    def state(self) -> HeavyConcreteState:
        """
        The current state of the emulator.
        """
        return self._state

    @property
    def breakpoints(self) -> set[int]:
        """
        The set of currently set breakpoints.
        """
        return self._engine.get_breakpoints()

    def add_breakpoint(self, addr: int) -> None:
        """
        Add a breakpoint at the given address.

        :param addr: The address to set the breakpoint at.
        """
        self._engine.add_breakpoint(addr)

    def remove_breakpoint(self, addr: int) -> None:
        """
        Remove a breakpoint at the given address, if present.

        :param addr: The address to remove the breakpoint from.
        """
        self._engine.remove_breakpoint(addr)

    def run(self, num_inst: int | None = None) -> EmulatorStopReason:
        """
        Execute the emulator.
        """
        completed_engine_execs = 0
        num_inst_executed: int = 0
        while self._state.history.jumpkind != "Ijk_Exit":
            # Check if there is a breakpoint at the current address
            if completed_engine_execs > 0 and self._state.addr in self._engine.get_breakpoints():
                return EmulatorStopReason.BREAKPOINT

            # Check if we've already executed the requested number of instructions
            if num_inst is not None and num_inst_executed >= num_inst:
                return EmulatorStopReason.INSTRUCTION_LIMIT

            # Calculate remaining instructions for this engine execution
            remaining_inst: int | None = None
            if num_inst is not None:
                remaining_inst = num_inst - num_inst_executed

            # Run the engine to get successors
            try:
                successors = self._engine.process(self._state, num_inst=remaining_inst)
            except EngineException as e:
                raise EngineException(f"Engine encountered an error: {e}") from e

            # Handle cases with an unexpected number of successors
            if len(successors.successors) == 0:
                return EmulatorStopReason.NO_SUCCESSORS
            if len(successors.successors) > 1:
                log.warning("Concrete engine returned multiple successors")

            # Set the state before raising further exceptions
            self._state = successors.successors[0]

            # Track the number of instructions executed using the state's history
            if self._state.history.recent_instruction_count > 0:
                num_inst_executed += self._state.history.recent_instruction_count

            if successors.successors[0].history.jumpkind == "Ijk_SigSEGV":
                return EmulatorStopReason.MEMORY_ERROR

            completed_engine_execs += 1

        return EmulatorStopReason.EXIT


__all__ = (
    "Emulator",
    "EmulatorException",
    "EmulatorStopReason",
    "EngineException",
    "StateDivergedException",
)

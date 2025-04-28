from __future__ import annotations
import logging
import random

from enum import auto, IntFlag
from collections.abc import Generator

import angr
from angr.analyses import Analysis, AnalysesHub
from angr.knowledge_plugins import Function
from angr.sim_state import SimState

from angr.utils.tagged_interval_map import TaggedIntervalMap


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class TraceActions(IntFlag):
    """
    Describe memory access actions.
    """

    WRITE = auto()
    EXECUTE = auto()


class TraceClassifier:
    """
    Classify traces.
    """

    def __init__(self, state: SimState | None = None):
        self.map = TaggedIntervalMap()
        if state:
            self.instrument(state)

    def act_mem_write(self, state) -> None:
        """
        SimInspect callback for memory writes.
        """
        addr = state.solver.eval(state.inspect.mem_write_address)
        length = state.inspect.mem_write_length
        if length is None:
            length = len(state.inspect.mem_write_expr) // state.arch.byte_width
        if not isinstance(length, int):
            length = state.solver.eval(length)
        self.map.add(addr, length, TraceActions.WRITE)

    def act_instruction(self, state) -> None:
        """
        SimInspect callback for instruction execution.
        """
        addr = state.inspect.instruction
        if addr is None:
            log.warning("Symbolic addr")
            return

        # FIXME: Ensure block size is correct
        self.map.add(addr, state.block().size, TraceActions.EXECUTE)

    def instrument(self, state) -> None:
        """
        Instrument `state` for tracing.
        """
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=self.act_mem_write)
        state.inspect.b("instruction", when=angr.BP_BEFORE, action=self.act_instruction)

    def get_smc_address_and_lengths(self) -> Generator[tuple[int, int]]:
        """
        Evaluate the trace to find which areas of memory were both written to and executed.
        """
        smc_flags = TraceActions.WRITE | TraceActions.EXECUTE
        for addr, size, flags in self.map.irange():
            if (flags & smc_flags) == smc_flags:
                yield (addr, size)

    def determine_smc(self) -> bool:
        """
        Evaluate the trace to find areas of memory that were both written to and executed.
        """
        return any(self.get_smc_address_and_lengths())

    def pp(self):
        for a, b, c in self.map.irange():
            print(f"{a:8x} {b} {c}")


class SelfModifyingCodeAnalysis(Analysis):
    """
    Determine if some piece of code is self-modifying.

    This determination is made by simply executing. If an address is executed
    that is also written to, the code is determined to be self-modifying. The
    determination is stored in the `result` property. The `regions` property
    contains a list of (addr, length) regions that were both written to and
    executed.
    """

    result: bool
    regions: list[tuple[int, int]]

    def __init__(self, subject: None | int | str | Function, max_bytes: int = 0, state: SimState | None = None):
        """
        :param subject: Subject of analysis
        :param max_bytes: Maximum number of bytes from subject address. 0 for no limit (default).
        :param state: State to begin executing from.
        """
        assert self.project.selfmodifying_code

        if subject is None:
            subject = self.project.entry
        if isinstance(subject, str):
            try:
                addr = self.project.kb.labels.lookup(subject)
            except KeyError:
                addr = self.project.kb.functions[subject].addr
        elif isinstance(subject, Function):
            addr = subject.addr
        elif isinstance(subject, int):
            addr = subject
        else:
            raise ValueError("Not a supported subject")

        if state is None:
            init_state = self.project.factory.call_state(addr)
        else:
            init_state = state.copy()
            init_state.regs.pc = addr

        init_state.options -= angr.sim_options.simplification

        self._trace_classifier = TraceClassifier(init_state)
        simgr = self.project.factory.simgr(init_state)

        kwargs = {}
        if max_bytes:
            kwargs["filter_func"] = lambda s: (
                "active" if s.solver.eval(addr <= s.regs.pc) and s.solver.eval(s.regs.pc < addr + max_bytes) else "oob"
            )

        # FIXME: Early out on SMC detect
        # FIXME: Configurable step threshold
        # FIXME: Loop analysis

        for n in range(100):
            self._update_progress(n)
            simgr.step(n=3)
            random.shuffle(simgr.active)
            simgr.split(from_stash="active", to_stash=simgr.DROP, limit=10)

        # Classify any out of bound entrypoints
        for state_ in simgr.stashes["oob"]:
            self._trace_classifier.act_instruction(state_)

        self.regions = list(self._trace_classifier.get_smc_address_and_lengths())
        self.result = len(self.regions) > 0


AnalysesHub.register_default("SMC", SelfModifyingCodeAnalysis)

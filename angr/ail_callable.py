from __future__ import annotations
from typing import TYPE_CHECKING

from collections.abc import Callable

from angr.engines.ail import ail_call_state
from angr.errors import AngrCallableError, AngrCallableMultistateError
from .callable import Callable as VEXCallable

if TYPE_CHECKING:
    from angr.analyses.decompiler.clinic import Clinic
    from angr.project import Project
    from angr.ailment import Address
    from angr.sim_manager import SimulationManager


class AILCallable(VEXCallable):
    """
    A Callable that uses AILCallState for its states.
    """

    def __init__(
        self,
        project: Project,
        addr: int | Address | str,
        lifter: Callable[[int], Clinic],
        mode: str = "symbolic",
        add_options: set[str] | None = None,
        remove_options: set[str] | None = None,
        preset: str = "default",
        boundary: set[int | Address] | None = None,
    ):
        super().__init__(project, addr, add_options=add_options, remove_options=remove_options)
        self._mode = mode
        self._lifter = lifter
        self._preset = preset
        self._boundary = boundary

    def perform_call(self, *args, prototype=None):
        state = ail_call_state(
            self._project,
            self._addr,
            args,
            self._lifter,
            mode=self._mode,
            add_options=self._add_options,
            remove_options=self._remove_options,
            plugin_preset=self._preset,
        )

        caller = self._project.factory.simulation_manager(state)
        caller.run(step_func=self._step_func).unstash(from_stash="deadended")
        caller.prune(filter_func=lambda pt: pt.addr == self._deadend_addr)

        if "step_limited" in caller.stashes:
            caller.stash(from_stash="step_limited", to_stash="active")
        if len(caller.active) == 0:
            raise AngrCallableError("No paths returned from function")

        self.result_path_group = caller.copy()

        if self._perform_merge:
            caller.merge()
            self.result_state = caller.active[0]
        elif len(caller.active) == 1:
            self.result_state = caller.active[0]

    def _step_func(self, pg: SimulationManager):
        pg2 = pg.prune()
        if self._concrete_only and len(pg2.active) > 1:
            raise AngrCallableMultistateError("Execution split on symbolic condition!")
        if self._step_limit:
            pg2.stash(filter_func=lambda p: p.history.depth >= self._step_limit, to_stash="step_limited")
        if self._boundary:
            pg2.stash(
                filter_func=lambda p: p.addr in self._boundary,
                to_stash="deadended",
            )
        return pg2

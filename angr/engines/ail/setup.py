from __future__ import annotations

# pylint: disable=import-outside-toplevel
from typing import TYPE_CHECKING
from collections.abc import Callable, Iterable

import claripy

from angr.engines.ail.callstack import AILCallStack
from angr.sim_state import SimState
from angr.storage.memory_mixins.memory_mixin import MemoryMixin

if TYPE_CHECKING:
    from angr.analyses.decompiler.clinic import Clinic
    from angr.project import Project
    from angr.ailment import Address


def ail_call_state(
    project: Project,
    start_addr: int | Address | str,
    args: Iterable[claripy.ast.Bits],
    lifter: Callable[[int], Clinic],
    mode: str = "symbolic",
    options: set[str] | None = None,
    add_options: set[str] | None = None,
    remove_options: set[str] | None = None,
    plugin_preset: str = "default",
    memory_cls: type[MemoryMixin] | None = None,
):
    state = SimState(
        project,
        project.arch,
        mode=mode,
        add_options=add_options,
        remove_options=remove_options,
        options=options,
        cle_memory_backer=project.loader.memory,
        plugin_preset=plugin_preset,
    )
    # break circular imports. this module should maybe live somewhere else
    from angr.storage import DefaultMemory

    state.globals["ail_var_memory_cls"] = memory_cls or DefaultMemory  # type: ignore
    state.globals["ail_lifter"] = lifter  # type: ignore

    if isinstance(start_addr, str):
        start_addr = project.kb.functions[start_addr].addr
    state.addr = (start_addr, None) if isinstance(start_addr, int) else start_addr

    bottom_frame = AILCallStack()
    top_frame = AILCallStack(func_addr=start_addr)
    top_frame.passed_args = tuple(args)
    state.register_plugin("callstack", bottom_frame)
    state.callstack.push(top_frame)

    return state

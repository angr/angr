from __future__ import annotations

from collections.abc import Callable, Iterable

# pylint: disable=import-outside-toplevel
from typing import TYPE_CHECKING

import claripy

from angr.engines.ail.callstack import AILCallStack
from angr.sim_state import SimState
from angr.storage.memory_mixins.memory_mixin import MemoryMixin

if TYPE_CHECKING:
    from angr.ailment import Address
    from angr.analyses.decompiler.clinic import Clinic
    from angr.project import Project


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
    callstack_cls: type[AILCallStack] | None = None,
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
    if isinstance(start_addr, int):
        state.addr = start_addr
        state.scratch.ail_block_idx = None
    else:
        state.addr = start_addr[0]
        state.scratch.ail_block_idx = start_addr[1]

    callstack_cls = callstack_cls or AILCallStack
    bottom_frame = callstack_cls()
    top_frame = callstack_cls(func_addr=start_addr)
    top_frame.passed_args = tuple(args)
    state.register_plugin("callstack", bottom_frame)
    state.callstack.push(top_frame)

    return state

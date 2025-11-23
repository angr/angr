from __future__ import annotations

# pylint: disable=wrong-import-position
from typing import TYPE_CHECKING
from collections.abc import Callable, Iterable
from angr.engines.ail.callstack import AILCallStack
from angr.sim_state import SimState
from angr.storage.memory_mixins.memory_mixin import MemoryMixin
import claripy

if TYPE_CHECKING:
    from angr.analyses.decompiler.clinic import Clinic
    from angr.project import Project
    from angr.knowledge_plugins.functions.function import Function


def ail_call_state(
    project: Project,
    func: Function | int | str,
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
    from angr.knowledge_plugins.functions.function import Function
    from angr.storage import DefaultMemory

    state.globals["ail_var_memory_cls"] = memory_cls or DefaultMemory
    state.globals["ail_lifter"] = lifter

    if not isinstance(func, Function):
        func = project.kb.functions[func]
    state.addr = (func.addr, None)

    bottom_frame = AILCallStack()
    top_frame = AILCallStack()
    top_frame.passed_args = tuple(args)
    state.register_plugin("callstack", bottom_frame)
    state.callstack.push(top_frame)

    return state

from __future__ import annotations

# pylint: disable=import-outside-toplevel
from typing import TYPE_CHECKING
from collections.abc import Callable, Iterable

import claripy

import angr
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
    # break circular imports. this module should maybe live somewhere else
    from angr.storage import DefaultMemory, DefaultAILMemory

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
    sim_memory = DefaultAILMemory(
        cle_memory_backer=project.loader.memory,
        dict_memory_backer=None,
        memory_id="mem",
        permissions_map=None,
        default_permissions=3,
        stack_perms=None,
        stack_end=None,
        stack_size=None,
    )
    state.register_plugin("memory", sim_memory)

    state.globals["ail_var_memory_cls"] = memory_cls or DefaultMemory  # type: ignore
    state.globals["ail_lifter"] = lifter  # type: ignore

    if isinstance(start_addr, str):
        start_addr = project.kb.functions[start_addr].addr
    state.addr = (start_addr, None) if isinstance(start_addr, int) else start_addr
    state.regs.sp = 0x7FFFFFFF

    bottom_frame = AILCallStack()
    top_frame = AILCallStack(func_addr=start_addr)
    top_frame.passed_args = tuple(mangle_arg(state, arg) for arg in args)
    state.register_plugin("callstack", bottom_frame)
    state.callstack.push(top_frame)

    return state


def mangle_arg(state, arg: int | angr.PointerWrapper | claripy.ast.Bits) -> claripy.ast.Bits:
    if isinstance(arg, int):
        return claripy.BVV(arg, 64)
    if isinstance(arg, claripy.ast.Bits):
        return arg
    if isinstance(arg, angr.PointerWrapper):
        wrapped = arg.value
        if isinstance(wrapped, str):
            wrapped = wrapped.encode() + b"\0"
        if isinstance(wrapped, bytes):
            wrapped = claripy.BVV(wrapped)
        size = len(wrapped) // 8
        state.regs.sp -= size
        state.memory.store(state.regs.sp, wrapped)
        return state.regs.sp
    raise TypeError(type(arg))

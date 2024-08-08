from __future__ import annotations
from typing import TYPE_CHECKING
import random

import archinfo
import claripy

from angr.analyses.reaching_definitions.function_handler import FunctionCallDataUnwrapped, FunctionHandler
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.knowledge_plugins.key_definitions.live_definitions import DerefSize


if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState

class EnvironAtom(Atom):
    def __init__(self, name: str | None):
        self.name = name
        super().__init__(1)

    def _identity(self):
        if self.name is not None:
            return (self.name,)
        else:
            return ()

    def __repr__(self):
        return f'<EnvironAtom {self.name if self.name is not None else "(dynamic)"}>'

class SystemAtom(Atom):
    def __init__(self):
        self.nonce = random.randint(0, 999999999999)
        super().__init__(1)

    def _identity(self):
        return (self.nonce,)

    def __repr__(self):
        return f'<SystemAtom>'


class ExecveAtom(Atom):
    def __init__(self, nonce: int, idx: int, size: int):
        self.nonce = nonce
        self.idx = idx
        super().__init__(size)

    def _identity(self):
        return (self.nonce,)

    def __repr__(self):
        return f'<ExecveAtom {self.idx}>'


class LibcStdlibHandlers(FunctionHandler):
    @FunctionCallDataUnwrapped.decorate
    def handle_impl_atoi(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        buf_atoms = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        buf_value = state.get_concrete_value(buf_atoms, cast_to=bytes)
        if buf_value is not None:
            buf_value = int(buf_value.decode().strip('\0'))
        data.depends(data.ret_atoms, buf_atoms, value=buf_value)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_malloc(self, state: "ReachingDefinitionsState", data: FunctionCallDataUnwrapped):
        malloc_size = state.get_concrete_value(data.args_atoms[0]) or 48
        heap_ptr = state.heap_allocator.allocate(malloc_size)
        data.depends(data.ret_atoms, value=state.heap_address(heap_ptr))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_getenv(self, state: "ReachingDefinitionsState", data: FunctionCallDataUnwrapped):
        name_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        name_value = state.get_concrete_value(name_atom, cast_to=bytes)
        if name_value is not None:
            name_value = name_value.strip(b'\0').decode()
        data.depends(None, name_atom)

        # store a buffer, registering it as an output of this function
        # we store this two-byte mixed value because we don't want the value to be picked up by get_concrete_value()
        # but also it should be able to be picked up by NULL_TERMINATE reads
        heap_ptr = state.heap_allocator.allocate(2)
        heap_atom = state.deref(heap_ptr, 2)
        heap_value = claripy.BVS('weh', 8).concat(claripy.BVV(0, 8))
        data.depends(heap_atom, EnvironAtom(name_value), value=heap_value)
        data.depends(data.ret_atoms, value=state.heap_address(heap_ptr))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strcpy(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src_atom = state.deref(data.args_atoms[1], DerefSize.NULL_TERMINATE)
        src_str = state.get_values(src_atom)
        if src_str is not None:
            dst_atom = state.deref(data.args_atoms[0], len(src_str) // 8)
            data.depends(dst_atom, src_atom, value=src_str)
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strncpy(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        n = state.get_concrete_value(data.args_atoms[1])
        src_atom = state.deref(data.args_atoms[2], DerefSize.NULL_TERMINATE if n is None else n)
        src_str = state.get_values(src_atom)
        if src_str is not None:
            dst_atom = state.deref(data.args_atoms[0], len(src_str) // 8)
            data.depends(dst_atom, src_atom, value=src_str)
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strdup(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src_atom = state.deref(data.args_atoms[1], DerefSize.NULL_TERMINATE)
        src_str = state.get_values(src_atom)
        if src_str is not None:
            malloc_size = len(src_str) // 8
        else:
            malloc_size = 1
        heap_ptr = state.heap_allocator.allocate(malloc_size)
        dst_atom = state.deref(heap_ptr, malloc_size)
        data.depends(dst_atom, src_atom, value=src_str)
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strcat(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src0_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        src1_atom = state.deref(data.args_atoms[1], DerefSize.NULL_TERMINATE)
        src0_value = state.get_values(src0_atom)
        src1_value = state.get_values(src1_atom)
        if src0_value is not None and src1_value is not None:
            src0_value = src0_value.extract(0, len(src0_value) // 8 - 1, archinfo.Endness.BE)
            dest_value = src0_value.concat(src1_value)
            dest_atom = state.deref(data.args_atoms[0], len(dest_value) // 8, endness=archinfo.Endness.BE)
        else:
            dest_value = None
            dest_atom = src0_atom
        data.depends(dest_atom, src0_atom, src1_atom, value=dest_value)
        data.depends(data.ret_atoms, data.args_atoms[0], value=src0_value)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strlen(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        src_str = state.get_values(src_atom)
        if src_str is not None:
            data.depends(data.ret_atoms, src_atom, value=len(src_str) // 8 - 1)
        else:
            data.depends(data.ret_atoms, src_atom)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_system(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        buf_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        data.depends(SystemAtom(), buf_atom)

    handle_impl_popen = handle_impl_execl = handle_impl_system

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_execve(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        argv_value = state.get_one_value(data.args_atoms[1])
        if argv_value is None:
            return

        nonce = random.randint(1, 999999999)

        # Iterate through each pointer in the array to collect argument strings
        idx = 0
        while True:
            # Read the concrete string pointer value
            argv_deref_atom = state.deref(argv_value, state.arch.bytes, state.arch.memory_endness)
            if argv_deref_atom is None:
                # unknown if array continues
                break

            argv_deref_concrete = state.get_concrete_value(argv_deref_atom)
            if argv_deref_concrete is None:
                # unknown if array continues
                break

            if argv_deref_concrete == 0:
                # End of array
                break

            string_atom = state.deref(argv_deref_concrete, DerefSize.NULL_TERMINATE)
            string_val = None if string_atom is None else state.get_values(string_atom)

            atom = ExecveAtom(nonce, idx, len(string_val) // 8 if string_val is not None else 1)
            data.depends(atom, [] if string_atom is None else [string_atom], value=string_val)

            # Increment by size of pointer for this arch
            argv_value += state.arch.bytes
            idx += 1


from __future__ import annotations
from typing import TYPE_CHECKING
import random

import claripy

from angr.analyses.reaching_definitions.function_handler import FunctionCallDataUnwrapped, FunctionHandler
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.knowledge_plugins.key_definitions.live_definitions import DerefSize
from angr.knowledge_plugins.key_definitions.definition import Definition

if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState

# pylint: disable=no-self-use,missing-class-docstring,unused-argument


class EnvironAtom(Atom):
    def __init__(self, size: int, name: str | None):
        self.name = name
        super().__init__(size)

    def _identity(self):
        if self.name is not None:
            return (self.name,)
        return ()

    def __repr__(self):
        return f'<EnvironAtom {self.name if self.name is not None else "(dynamic)"}>'


class SystemAtom(Atom):
    def __init__(self, size: int = 1):
        self.nonce = random.randint(0, 999999999999)
        super().__init__(size)

    def _identity(self):
        return (self.nonce,)

    def __repr__(self):
        return "<SystemAtom>"


class ExecveAtom(Atom):
    def __init__(self, nonce: int, idx: int, size: int):
        self.nonce = nonce
        self.idx = idx
        super().__init__(size)

    def _identity(self):
        return (self.nonce, self.idx)

    def __repr__(self):
        return f"<ExecveAtom {self.idx}>"


class LibcStdlibHandlers(FunctionHandler):
    @FunctionCallDataUnwrapped.decorate
    def handle_impl_atoi(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        buf_atoms = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        buf_value = state.get_concrete_value(buf_atoms, cast_to=bytes)
        if buf_value is not None:
            try:
                buf_value = int(buf_value.decode().strip("\0"))
            except ValueError:
                buf_value = 0
        else:
            buf_value = 0  # Make the value concrete if it cannot be parsed
        data.depends(data.ret_atoms, buf_atoms, value=buf_value)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_malloc(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        malloc_size = state.get_concrete_value(data.args_atoms[0]) or 48
        heap_ptr = state.heap_allocator.allocate(malloc_size)
        heap_addr = state.heap_address(heap_ptr)
        data.depends(data.ret_atoms, value=heap_addr)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_calloc(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        nmemb = state.get_concrete_value(data.args_atoms[0]) or 48
        size = state.get_concrete_value(data.args_atoms[1]) or 1
        heap_ptr = state.heap_allocator.allocate(nmemb * size)
        heap_addr = state.heap_address(heap_ptr)
        data.depends(state.deref(heap_addr, nmemb * size), value=0)
        data.depends(data.ret_atoms, value=heap_addr)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_getenv(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        name_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        name_value = state.get_concrete_value(name_atom, cast_to=bytes)
        length = 2
        heap_value = None

        data.depends(None, name_atom)

        # store a buffer, registering it as an output of this function
        # we store this two-byte mixed value because we don't want the value to be picked up by get_concrete_value()
        # but also it should be able to be picked up by NULL_TERMINATE reads
        heap_atom = None
        env_atom = None
        heap_ptr = None
        sources = []
        if name_value is not None:
            name_value = name_value.strip(b"\0").decode()
            for env_atom, env_value in state.others.items():
                if not isinstance(env_atom, EnvironAtom) or env_atom.name != name_value:
                    continue

                # There exists an environment variable with this name
                heap_value = env_value
                length = env_atom.size
                heap_ptr = state.heap_allocator.allocate(length)
                heap_atom = state.deref(heap_ptr, length)
                break

            else:
                heap_value = None

        if name_value is None or heap_value is None or heap_atom is None or env_atom is None:
            heap_ptr = state.heap_allocator.allocate(length)
            heap_atom = state.deref(heap_ptr, length)
            heap_value = claripy.BVS("weh", 8)
            env_atom = EnvironAtom(length, name_value)
            if heap_atom is not None:
                heap_value = state.annotate_with_def(heap_value, Definition(heap_atom, state.codeloc))
            heap_value = heap_value.concat(claripy.BVV(0, 8))
            data.depends(env_atom, value=heap_value)  # Puts the env_atom in the others dict

        data.depends(heap_atom, env_atom, value=heap_value)
        sources = [heap_atom, env_atom]
        if name_atom is not None:
            sources.append(name_atom)

        value = state.heap_address(heap_ptr) if heap_ptr is not None else state.top(state.arch.bits)
        data.depends(data.ret_atoms, *sources, value=value)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_setenv(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        name_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        name_value = state.get_concrete_value(name_atom, cast_to=bytes)
        if name_value is not None:
            name_value = name_value.strip(b"\0").decode()
        data.depends(None, name_atom)

        src_atom = state.deref(data.args_atoms[1], DerefSize.NULL_TERMINATE)
        src_value = state.get_values(src_atom)

        env_atom = EnvironAtom(len(src_value) // 8 if src_value is not None else 1, name_value)
        data.depends(env_atom, src_atom, value=src_value)

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_system(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        buf_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        buf_value = state.get_values(buf_atom)
        data.depends(SystemAtom(len(buf_value) // 8 if buf_value is not None else 1), buf_atom, value=buf_value)

    handle_impl_popen = handle_impl_execl = handle_impl_system

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_execve(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        argv_value = state.get_one_value(data.args_atoms[1])
        if argv_value is None:
            # Model execve with unknown argv - still has system effects
            data.depends(SystemAtom(1), data.args_atoms[0], value=state.get_values(data.args_atoms[0]))
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

            argv_deref_concrete = state.get_one_value(argv_deref_atom)
            if argv_deref_concrete is None:
                # unknown if array continues
                break

            if (argv_deref_concrete == 0).is_true():
                # End of array
                break

            string_atom = state.deref(argv_deref_concrete, DerefSize.NULL_TERMINATE)
            string_val = None if string_atom is None else state.get_values(string_atom)

            atom = ExecveAtom(nonce, idx, len(string_val) // 8 if string_val is not None else 1)
            data.depends(atom, [] if string_atom is None else [string_atom], value=string_val)

            # Increment by size of pointer for this arch
            argv_value += state.arch.bytes
            idx += 1

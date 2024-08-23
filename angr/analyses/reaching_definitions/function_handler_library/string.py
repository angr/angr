from __future__ import annotations
import archinfo
from angr.analyses.reaching_definitions.function_handler import FunctionCallDataUnwrapped, FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.knowledge_plugins.key_definitions.live_definitions import DerefSize

# pylint: disable=no-self-use,missing-class-docstring,unused-argument


class LibcStringHandlers(FunctionHandler):
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

    handle_impl_strncat = handle_impl_strcat

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strlen(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        src_str = state.get_values(src_atom)
        if src_str is not None:
            data.depends(data.ret_atoms, src_atom, value=len(src_str) // 8 - 1)
        else:
            data.depends(data.ret_atoms, src_atom)

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
        malloc_size = len(src_str) // 8 if src_str is not None else 1
        heap_ptr = state.heap_allocator.allocate(malloc_size)
        dst_atom = state.deref(heap_ptr, malloc_size)
        data.depends(dst_atom, src_atom, value=src_str)
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_memcpy(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[2])
        if size is not None:
            src_atom = state.deref(data.args_atoms[1], size)
            dst_atom = state.deref(data.args_atoms[0], size)
            data.depends(dst_atom, src_atom, value=state.get_values(src_atom))
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_memset(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[2])
        if size is not None:
            dst_atom = state.deref(data.args_atoms[0], size)
            data.depends(dst_atom, data.args_atoms[1])
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strtok(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        # stub: just return the haystack pointer
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    handle_impl_strtok_r = handle_impl_strstr = handle_impl_strcasestr = handle_impl_strchr = handle_imple_strrchr = (
        handle_impl_strchrnul
    ) = handle_impl_strtok

from __future__ import annotations
import archinfo
import claripy
from angr.analyses.reaching_definitions.function_handler import FunctionCallDataUnwrapped, FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.knowledge_plugins.key_definitions.live_definitions import DerefSize
from angr.knowledge_plugins.key_definitions.live_definitions import MultiValues

# pylint: disable=no-self-use,missing-class-docstring,unused-argument


class LibcStringHandlers(FunctionHandler):
    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strcat(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src0_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        src1_atom = state.deref(data.args_atoms[1], DerefSize.NULL_TERMINATE)
        src0_value = state.get_values(src0_atom) if src0_atom is not None else None
        src1_value = state.get_values(src1_atom) if src1_atom is not None else None

        if src0_value is not None and src1_value is not None:
            src0_value = src0_value.extract(0, len(src0_value) // 8 - 1, archinfo.Endness.BE)
            dest_value = src0_value.concat(src1_value)
            dest_atom = state.deref(data.args_atoms[0], len(dest_value) // 8, endness=archinfo.Endness.BE)
        elif src0_value is not None:
            src0_value = src0_value.extract(0, len(src0_value) // 8 - 1, archinfo.Endness.BE)
            top_val = state.top(state.arch.bits)
            if src1_atom is not None:
                for defn in state.get_definitions(src1_atom):
                    top_val = state.annotate_with_def(top_val, defn)
            dest_value = src0_value.concat(MultiValues(top_val))
            dest_atom = state.deref(data.args_atoms[0], len(dest_value) // 8, endness=archinfo.Endness.BE)
        else:
            dest_value = None
            dest_atom = src0_atom
        if src0_atom is not None and src1_atom is not None:
            data.depends(dest_atom, src0_atom, src1_atom, value=dest_value)
        data.depends(data.ret_atoms, data.args_atoms[0], value=src0_value)

    handle_impl_strncat = handle_impl_strcat

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strlen(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        if src_atom is not None:
            src_str = state.get_values(src_atom) if src_atom is not None else None
            if src_str is not None:
                data.depends(data.ret_atoms, src_atom, value=len(src_str) // 8 - 1)
            else:
                data.depends(data.ret_atoms, src_atom)
        else:
            data.depends(data.ret_atoms, data.args_atoms[0])

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strcpy(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src_atom = state.deref(data.args_atoms[1], DerefSize.NULL_TERMINATE)
        src_str = state.get_values(src_atom) if src_atom is not None else None
        if src_str is None:
            src_str = state.top(state.arch.bits)
            if src_atom is not None:
                for defn in state.get_definitions(src_atom):
                    src_str = state.annotate_with_def(src_str, defn)
            src_str = MultiValues(src_str)

        dst_atom = state.deref(data.args_atoms[0], len(src_str) // 8)
        if src_atom is not None:
            data.depends(dst_atom, src_atom, value=src_str)
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strncpy(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        n = state.get_concrete_value(data.args_atoms[2])
        src_atom = state.deref(data.args_atoms[1], DerefSize.NULL_TERMINATE)
        src_str = state.get_values(src_atom) if src_atom is not None else None
        if src_str is None and src_atom is not None:
            tmp_atom = state.deref(data.args_atoms[1], 1)
            if tmp_atom is not None:
                tmp_str = state.get_values(tmp_atom)
                val_defns = None if tmp_str is None else state.get_definitions(tmp_str)
                if tmp_str is None or not val_defns:  # There's no data at all or no valid definitions
                    src_str = state.top(state.arch.bits if n is None or n > state.arch.bytes else n * 8)
                    defns = state.get_definitions(src_atom) if src_atom is not None else []
                    for defn in defns:
                        src_str = state.annotate_with_def(src_str, defn)
                    src_str = MultiValues(src_str)
                else:  # We found some data, but it's not NULL_TERIMINATED or of size n
                    src_atoms = set()
                    for defn in val_defns:
                        a = defn.atom
                        a.size = a.size if n is None or a.size < n else n
                        src_atoms.add(a)
                    src_str = state.get_values(src_atoms)

        elif n is not None and src_str is not None and n < len(src_str) // 8:
            # We have a src_str, but need to truncate it if n is not None and less than the size of src_str
            src_atom = state.deref(data.args_atoms[1], n)
            if src_atom is not None:
                src_str = state.get_values(src_atom)

        if src_str is not None and src_atom is not None:
            dst_atom = state.deref(data.args_atoms[0], len(src_str) // 8)
            data.depends(dst_atom, src_atom, value=src_str)

        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strdup(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        src_atom = state.deref(data.args_atoms[0], DerefSize.NULL_TERMINATE)
        if src_atom is not None:
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
            if src_atom is not None:
                data.depends(dst_atom, src_atom, value=state.get_values(src_atom))
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_memset(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[2])
        c = state.get_concrete_value(data.args_atoms[1])
        if size is not None:
            dst_atom = state.deref(data.args_atoms[0], size)
            if c is not None:
                value = MultiValues(claripy.BVV(chr(c) * size, size * 8))
                data.depends(dst_atom, data.args_atoms[1], value=value)
            else:
                data.depends(dst_atom, data.args_atoms[1], value=state.get_values(data.args_atoms[1]))

        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_strtok(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        # stub: just return the haystack pointer
        data.depends(data.ret_atoms, data.args_atoms[0], value=state.get_values(data.args_atoms[0]))

    handle_impl_strtok_r = handle_impl_strstr = handle_impl_strcasestr = handle_impl_strchr = handle_imple_strrchr = (
        handle_impl_strchrnul
    ) = handle_impl_strtok

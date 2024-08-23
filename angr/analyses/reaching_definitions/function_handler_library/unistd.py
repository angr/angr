from __future__ import annotations
from angr.analyses.reaching_definitions.function_handler import FunctionCallDataUnwrapped, FunctionHandler
from angr.analyses.reaching_definitions.function_handler_library.stdio import StdinAtom, StdoutAtom
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState

# pylint: disable=no-self-use,missing-class-docstring,unused-argument


class LibcUnistdHandlers(FunctionHandler):
    @FunctionCallDataUnwrapped.decorate
    def handle_impl_read(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[2]) or 1
        dst_atom = state.deref(data.args_atoms[1], size)
        data.depends(dst_atom, StdinAtom(data.function.name, size))

    handle_impl_recv = handle_impl_recvfrom = handle_impl_read

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_write(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[2]) or 1
        src_atom = state.deref(data.args_atoms[1], size)
        data.depends(StdoutAtom(data.function.name, size), src_atom, value=state.get_values(src_atom))

    handle_impl_send = handle_impl_write

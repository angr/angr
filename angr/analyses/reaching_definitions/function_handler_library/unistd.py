from __future__ import annotations
import random
from angr.analyses.reaching_definitions.function_handler import FunctionCallDataUnwrapped, FunctionHandler
from angr.analyses.reaching_definitions.function_handler_library.stdio import StdinAtom, StdoutAtom
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.knowledge_plugins.key_definitions.atoms import Atom

# pylint: disable=no-self-use,missing-class-docstring,unused-argument


class FDAtom(Atom):
    def __init__(self, fd: int | None, source: str, size: int = 1):
        self.source = source
        self.fd = fd
        self.nonce = random.randint(0, 999999999999)
        super().__init__(size)

    def _identity(self):
        if self.fd is not None:
            return (self.fd,)
        return (self.nonce,)


class LibcUnistdHandlers(FunctionHandler):
    @FunctionCallDataUnwrapped.decorate
    def handle_impl_read(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[2]) or 1
        dst_atom = state.deref(data.args_atoms[1], size)
        real_fd = state.get_concrete_value(data.args_atoms[0])

        fd_atom = StdinAtom(data.function.name, size) if real_fd == 0 else FDAtom(real_fd, data.function.name, size)
        buf_data = state.top(size * 8) if size is not None else state.top(state.arch.bits)

        data.depends(dst_atom, fd_atom, value=buf_data)

    handle_impl_recv = handle_impl_recvfrom = handle_impl_read

    @FunctionCallDataUnwrapped.decorate
    def handle_impl_write(self, state: ReachingDefinitionsState, data: FunctionCallDataUnwrapped):
        size = state.get_concrete_value(data.args_atoms[2]) or 1
        src_atom = state.deref(data.args_atoms[1], size)
        data.depends(StdoutAtom(data.function.name, size), src_atom, value=state.get_values(src_atom))

    handle_impl_send = handle_impl_write

from __future__ import annotations
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import angr


def mode_to_flag(mode):
    # TODO improve this: handle mode = strings
    if mode[-1] == ord("b") or mode[-1] == ord("t"):  # lol who uses windows
        mode = mode[:-1]
    mode = mode.replace(b"c", b"").replace(b"e", b"")
    all_modes = {
        b"r": angr.storage.file.Flags.O_RDONLY,
        b"r+": angr.storage.file.Flags.O_RDWR,
        b"w": angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT,
        b"w+": angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT,
        b"a": angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND,
        b"a+": angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND,
    }
    if mode not in all_modes:
        raise angr.SimProcedureError(f"unsupported file open mode {mode}")

    return all_modes[mode]


class fopen(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, p_addr, m_addr):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]

        p_strlen = self.inline_call(strlen, p_addr)
        m_strlen = self.inline_call(strlen, m_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness="Iend_BE")
        m_expr = self.state.memory.load(m_addr, m_strlen.max_null_index, endness="Iend_BE")
        path = self.state.solver.eval(p_expr, cast_to=bytes)
        mode = self.state.solver.eval(m_expr, cast_to=bytes)

        # TODO: handle append
        fd = self.state.posix.open(path, mode_to_flag(mode))
        fd_concr = self.state.posix.get_concrete_fd(fd)

        if fd_concr == -1:
            # if open failed return NULL
            return 0

        # Allocate a FILE struct in heap
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        io_file_data = io_file_data_for_arch(self.state.arch)
        file_struct_ptr = self.inline_call(malloc, io_file_data["size"]).ret_expr

        # Write the fd
        size = 4  # int
        self.state.memory.store(
            file_struct_ptr + io_file_data["fd"], fd, size=size, endness=self.state.arch.memory_endness
        )

        if self.state.solver.is_true(fd == fd_concr):
            return file_struct_ptr
        # still possible that open failed
        null = claripy.BVV(0, self.state.arch.bits)
        return claripy.If(fd == fd_concr, file_struct_ptr, null)

import angr

from ..libc import io_file_data_for_arch

######################################
# fdopen
#
# Reference for implementation:
#   glibc-2.25/libio/iofdopen.c
######################################


def mode_to_flag(mode):
    # TODO improve this: handle mode = strings
    if mode[-1] == 'b': # lol who uses windows
        mode = mode[:-1]
    all_modes = {
        "r"  : angr.storage.file.Flags.O_RDONLY,
        "r+" : angr.storage.file.Flags.O_RDWR,
        "w"  : angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT,
        "w+" : angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT,
        "a"  : angr.storage.file.Flags.O_WRONLY | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND,
        "a+" : angr.storage.file.Flags.O_RDWR | angr.storage.file.Flags.O_CREAT | angr.storage.file.Flags.O_APPEND
        }
    if mode not in all_modes:
        raise angr.SimProcedureError('unsupported file open mode %s' % mode)

    return all_modes[mode]

class fdopen(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd_int, m_addr):
        #pylint:disable=unused-variable
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        m_strlen = self.inline_call(strlen, m_addr)
        m_expr = self.state.memory.load(m_addr, m_strlen.max_null_index, endness='Iend_BE')
        mode = self.state.se.eval(m_expr, cast_to=str)

        # TODO: handle append and other mode subtleties

        fd = self.state.se.eval(fd_int)
        if fd not in self.state.posix.fd:
            # if file descriptor not found return NULL
            return 0
        else:
            # Allocate a FILE struct in heap
            malloc = angr.SIM_PROCEDURES['libc']['malloc']
            io_file_data = io_file_data_for_arch(self.state.arch)
            file_struct_ptr = self.inline_call(malloc, io_file_data['size']).ret_expr

            # Write the fd
            fd_bvv = self.state.se.BVV(fd, 4 * 8) # int
            self.state.memory.store(file_struct_ptr + io_file_data['fd'],
                                    fd_bvv,
                                    endness=self.state.arch.memory_endness)

            return file_struct_ptr

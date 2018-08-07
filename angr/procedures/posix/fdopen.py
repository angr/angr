import angr

from ..libc import files

######################################
# fdopen
#
# Reference for implementation:
#   glibc-2.25/libio/iofdopen.c
######################################


class fdopen(files.FileProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd_int, m_addr):
        #pylint:disable=unused-variable
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        m_strlen = self.inline_call(strlen, m_addr)
        m_expr = self.state.memory.load(m_addr, m_strlen.max_null_index, endness='Iend_BE')
        mode = self.state.se.eval(m_expr, cast_to=str)

        # TODO: handle append and other mode subtleties

        if self.state.posix.get_fd(fd_int) is None:
            # if open failed return NULL
            return 0
        else:
            # Allocate a FILE struct in heap
            malloc = angr.SIM_PROCEDURES['libc']['malloc']
            ptr = self.inline_call(malloc, files.FILE.max_size(self.state.arch)).ret_expr
            fp = self.get_file(ptr)
            fp.fd = fd_int
            fp.ungetc = None
            return ptr


from __future__ import annotations

import logging

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import angr
from angr import claripy

l = logging.getLogger(name=__name__)


class getdelim(angr.SimProcedure):
    # this code is modified from the 'fgets' implementation
    #   to take an arbitrary delimiter
    #   with no max size for concrete data

    def _caller_buffer(self, line_ptrptr, len_ptr):
        """
        Return (*lineptr, capacity). The capacity is *n if the caller passed a non-NULL buffer with a concrete size,
        which is reused until it is too small as in glibc, and 0 otherwise.
        """
        line_ptr = self.state.memory.load(line_ptrptr, self.arch.bytes, endness=self.arch.memory_endness)
        n = self.state.memory.load(len_ptr, self.arch.bytes, endness=self.arch.memory_endness)
        if self.state.solver.symbolic(line_ptr) or self.state.solver.symbolic(n):
            return line_ptr, 0
        if self.state.solver.eval(line_ptr) == 0:
            return line_ptr, 0
        return line_ptr, self.state.solver.eval(n)

    # pylint: disable=arguments-differ
    def run(self, line_ptrptr, len_ptr, delim, file_ptr):
        # let's get the memory back for the file we're interested in and find the delimiter
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fd = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        # symbolic delimiters will make this tricky
        if delim.symbolic:
            raise angr.SimProcedureError("I don't know how to handle a symbolic delimiter")

        # case 1: the data is concrete. we should read it a byte at a time since we can't seek for
        # the newline and we don't have any notion of buffering in-memory
        if simfd.read_storage.concrete:
            if self.state.solver.is_true(simfd.eof()):
                # End-of-file reached
                return -1

            realloc = angr.SIM_PROCEDURES["libc"]["realloc"]

            dst, size = self._caller_buffer(line_ptrptr, len_ptr)
            if size == 0:
                size = 120
                dst = self.inline_call(realloc, dst, size).ret_expr

            count = 0
            while True:
                data, real_size = simfd.read_data(1)
                if self.state.solver.is_true(real_size == 0):
                    break
                self.state.memory.store(dst + count, data)
                count += 1
                if count == size:
                    size = count + size + 1
                    dst = self.inline_call(realloc, dst, size).ret_expr
                # glibc compares against (unsigned char)delim
                if self.state.solver.is_true(data == delim[7:0]):
                    break

            self.state.memory.store(dst + count, b"\0")
            # *n is the buffer's capacity, not the line length
            self.state.memory.store(len_ptr, size, size=self.arch.bytes, endness=self.arch.memory_endness)
            self.state.memory.store(line_ptrptr, dst, endness=self.arch.memory_endness)
            return count

        # case 2: the data is symbolic, the delimiter could be anywhere. Read some maximum number of bytes
        # and add a constraint to assert the delimiter nonsense.
        # caveat: there could also be no delimiter and the file could EOF.
        # Just a guess as to a good value for a max size
        size = 1024

        data, real_size = simfd.read_data(size - 1)
        delim_byte = delim[7:0]

        for i, byte in enumerate(data.chop(8)):
            self.state.add_constraints(
                claripy.If(
                    i + 1 != real_size,
                    byte != delim_byte,  # if not last byte returned, not newline
                    claripy.Or(  # otherwise one of the following must be true:
                        i + 2 == size,  # - we ran out of space, or
                        simfd.eof(),  # - the file is at EOF, or
                        byte == delim_byte,  # - it is a newline
                    ),
                )
            )

        if isinstance(real_size, int):
            real_size = claripy.BVV(real_size, self.arch.bits)
        elif real_size.size() < self.arch.bits:
            real_size = real_size.zero_extend(self.arch.bits - real_size.size())

        # one extra byte for the NUL terminator
        buf_size = real_size + 1
        dst, capacity = self._caller_buffer(line_ptrptr, len_ptr)
        if capacity != 0 and self.state.solver.is_true(claripy.ULE(buf_size, capacity)):
            buf_size = claripy.BVV(capacity, self.arch.bits)
        else:
            # malloc, not realloc: the line is written from offset 0, and realloc would pin a symbolic size
            malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
            dst = self.inline_call(malloc, buf_size).ret_expr

        self.state.memory.store(dst, data, size=real_size)
        self.state.memory.store(dst + real_size, b"\0")

        self.state.memory.store(len_ptr, buf_size, endness=self.arch.memory_endness)
        self.state.memory.store(line_ptrptr, dst, endness=self.arch.memory_endness)

        return real_size

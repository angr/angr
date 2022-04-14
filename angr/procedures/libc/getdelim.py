import angr
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import logging

l = logging.getLogger(name=__name__)

######################################
# __getdelim
######################################

class __getdelim(angr.SimProcedure):
    # this code is modified from the 'fgets' implementation
    #   to take an arbitrary delimiter
    #   with no max size for concrete data

    # pylint: disable=arguments-differ
    def run(self, line_ptrptr, len_ptr, delim, file_ptr):
        # let's get the memory back for the file we're interested in and find the delimiter
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
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

            realloc = angr.SIM_PROCEDURES['libc']['realloc']

            # #dereference the destination buffer
            line_ptr = self.state.memory.load(line_ptrptr,8)
            size = 120
            # im just always going to realloc and restart at size = 120, regardless of if a proper size buffer exists.
            # this doesn't match the exact behavior of get delim, but is the easiest way to ignore symbolic sizes.
            dst = self.inline_call(realloc, line_ptr, size).ret_expr

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
                if delim.size() > data.size():
                    data = data.zero_extend(delim.size() - data.size())
                if self.state.solver.is_true(data == delim):
                    break

            self.state.memory.store(dst + count, b'\0')
            self.state.memory.store(len_ptr,count)
            self.state.memory.store(line_ptrptr,dst)
            return count


        # case 2: the data is symbolic, the delimiter could be anywhere. Read some maximum number of bytes
        # and add a constraint to assert the delimiter nonsense.
        # caveat: there could also be no delimiter and the file could EOF.
        else:
            # Just a guess as to a good value for a max size
            size = 1024

            data, real_size = simfd.read_data(size-1)
            delim_byte = chr(self.state.solver.eval(delim))

            for i, byte in enumerate(data.chop(8)):
                self.state.add_constraints(self.state.solver.If(
                    i+1 != real_size, byte != delim_byte, # if not last byte returned, not newline
                    self.state.solver.Or(            # otherwise one of the following must be true:
                        i+2 == size,                 # - we ran out of space, or
                        simfd.eof(),                 # - the file is at EOF, or
                        byte == delim_byte                # - it is a newline
                    )))

            malloc = angr.SIM_PROCEDURES['libc']['malloc']

            dst = self.inline_call(malloc,real_size).ret_expr

            self.state.memory.store(dst, data, size=real_size)
            self.state.memory.store(dst+real_size, b'\0')

            self.state.memory.store(len_ptr,real_size)
            self.state.memory.store(line_ptrptr,dst)

            return real_size

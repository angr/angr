import angr
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation


from cle.backends.externs.simdata.io_file import io_file_data_for_arch

######################################
# fgets
######################################

class fgets(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, file_ptr):
        size = size.zero_extend(self.arch.bits - self.arch.sizeof['int'])

        # let's get the memory back for the file we're interested in and find the newline
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        # case 0: empty read
        if self.state.solver.is_true(size == 0):
            return 0

        # case 1: the data is concrete. we should read it a byte at a time since we can't seek for
        # the newline and we don't have any notion of buffering in-memory
        elif simfd.read_storage.concrete and not size.symbolic:
            size = self.state.solver.eval(size)
            count = 0
            while count < size - 1:
                data, real_size = simfd.read_data(1)
                if self.state.solver.is_true(real_size == 0):
                    break
                self.state.memory.store(dst + count, data)
                count += 1
                if self.state.solver.is_true(data == b'\n'):
                    break
            self.state.memory.store(dst + count, b'\0')
            return count

        # case 2: the data is symbolic, the newline could be anywhere. Read the maximum number of bytes
        # (SHORT_READS should take care of the variable length) and add a constraint to assert the
        # newline nonsense.
        # caveat: there could also be no newline and the file could EOF.
        else:
            data, real_size = simfd.read_data(size-1)

            for i, byte in enumerate(data.chop(8)):
                self.state.add_constraints(self.state.solver.If(
                    i+1 != real_size, byte != b'\n', # if not last byte returned, not newline
                    self.state.solver.Or(            # otherwise one of the following must be true:
                        i+2 == size,                 # - we ran out of space, or
                        simfd.eof(),                 # - the file is at EOF, or
                        byte == b'\n'                # - it is a newline
                    )))
            self.state.memory.store(dst, data, size=real_size)
            end_address = dst + real_size
            end_address = end_address.annotate(MultiwriteAnnotation())
            self.state.memory.store(end_address, b'\0')

            return real_size

fgets_unlocked = fgets

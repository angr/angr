import logging

import angr
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation
from angr.misc.ux import once

_l = logging.getLogger(name=__name__)


######################################
# gets
######################################


class gets(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, dst):
        if once("gets_warning"):
            _l.warning(
                "The use of gets in a program usually causes buffer overflows. You may want to adjust "
                "SimStateLibc.max_gets_size to properly mimic an overflowing read."
            )

        fd = 0
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return 0

        max_size = self.state.libc.max_gets_size

        # case 0: the data is concrete. we should read it a byte at a time since we can't seek for
        # the newline and we don't have any notion of buffering in-memory
        if simfd.read_storage.concrete:
            count = 0
            while count < max_size - 1:
                data, real_size = simfd.read_data(1)
                if self.state.solver.is_true(real_size == 0):
                    break
                self.state.memory.store(dst + count, data)
                count += 1
                if self.state.solver.is_true(data == b"\n"):
                    break
            self.state.memory.store(dst + count, b"\0")
            return dst

        # case 2: the data is symbolic, the newline could be anywhere. Read the maximum number of bytes
        # (SHORT_READS should take care of the variable length) and add a constraint to assert the
        # newline nonsense.
        # caveat: there could also be no newline and the file could EOF.
        else:
            data, real_size = simfd.read_data(max_size - 1)

            for i, byte in enumerate(data.chop(8)):
                self.state.add_constraints(
                    self.state.solver.If(
                        i + 1 != real_size,
                        byte != b"\n",  # if not last byte returned, not newline
                        self.state.solver.Or(  # otherwise one of the following must be true:
                            i + 2 == max_size,  # - we ran out of space, or
                            simfd.eof(),  # - the file is at EOF, or
                            byte == b"\n",  # - it is a newline
                        ),
                    )
                )
            self.state.memory.store(dst, data, size=real_size)
            end_address = dst + real_size
            end_address = end_address.annotate(MultiwriteAnnotation())
            self.state.memory.store(end_address, b"\0")

            return dst

import simuvex
from simuvex.s_type import SimTypeTop, SimTypeInt, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.memset")

######################################
# memset
######################################

class memset(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    @staticmethod
    def _repeat_bytes(byt, rep):
        """
        Get a long number for a byte being repeated for many times. This is part of the effort of optimizing
        performance of angr's memory operations.

        :param int byt: the byte to repeat
        :param int rep: times to repeat the byte
        :return: a long integer representing the repeating bytes
        ;rtype: int
        """

        if rep == 1:
            return byt

        remainder = rep % 2
        quotient = rep / 2

        r_ = memset._repeat_bytes(byt, quotient)
        if remainder == 1:
            r = r_ << ((quotient + 1) * 8)
            r |= (r_ << 8) + byt
        else:
            r = r_ << (quotient * 8)
            r |= r_
        return r

    def run(self, dst_addr, char, num):
        char = char[7:0]

        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                       1: SimTypeInt(32, True), # ?
                       2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop())

        if self.state.se.symbolic(num):
            l.debug("symbolic length")
            max_size = self.state.se.min_int(num) + self.state.libc.max_buffer_size
            write_bytes = self.state.se.Concat(*([ char ] * max_size))
            self.state.memory.store(dst_addr, write_bytes, size=num)
        else:
            max_size = self.state.se.any_int(num)
            if max_size == 0:
                return 0

            # Concatenating many bytes is slow, so some sort of optimization is required
            if char._model_concrete.value == 0:
                write_bytes = self.state.se.BVV(0, max_size * 8)
            else:
                rb = memset._repeat_bytes(char._model_concrete.value, max_size)
                write_bytes = self.state.se.BVV(rb, max_size * 8)
            self.state.memory.store(dst_addr, write_bytes)

            l.debug("memset writing %d bytes", max_size)

        return dst_addr

from simuvex.procedures.cgc.receive import receive

import logging
l = logging.getLogger("tracer.simprocedures.FixedInReceive")

class FixedInReceive(receive):
    # pylint:disable=arguments-differ
    """
    Transmit which fixes the output file descriptor to 1.
    """

    def run(self, fd, buf, count, rx_bytes):

        if self.state.se.any_n_int(fd, 2) < 2:
            if self.state.se.any_int(fd) == 1:
                l.debug("fixed receive call's fd")
                fd = self.state.se.BVV(0, self.state.arch.bits)

        return super(FixedInReceive, self).run(fd, buf, count, rx_bytes)

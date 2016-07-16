from simuvex.procedures.cgc.transmit import transmit

import logging
l = logging.getLogger("tracer.simprocedures.FixedOutTransmit")

class FixedOutTransmit(transmit):
    # pylint:disable=arguments-differ
    """
    Transmit which fixes the output file descriptor to 1.
    """

    def run(self, fd, buf, count, tx_bytes):

        if len(self.state.se.any_n_int(fd, 2)) < 2:
            if self.state.se.any_int(fd) == 0:
                l.debug("fixed transmit's call fd")
                fd = self.state.se.BVV(1, self.state.arch.bits)

        if self.state.has_plugin("zen_plugin"):
            self.state.get_plugin("zen_plugin").analyze_transmit(self.state, buf)

        return super(FixedOutTransmit, self).run(fd, buf, count, tx_bytes)

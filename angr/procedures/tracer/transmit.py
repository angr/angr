import logging

from ..cgc.transmit import transmit as orig_transmit


l = logging.getLogger("angr.procedures.tracer.transmit")


class transmit(orig_transmit):
    # pylint:disable=arguments-differ
    """
    Transmit which fixes the output file descriptor to 1.
    """

    def run(self, fd, buf, count, tx_bytes):
        if len(self.state.se.eval_upto(fd, 2)) < 2:
            if self.state.se.eval(fd) == 0:
                l.debug("Fixed transmit's call fd.")
                fd = self.state.se.BVV(1, self.state.arch.bits)

        if self.state.has_plugin("zen_plugin"):
            self.state.get_plugin("zen_plugin").analyze_transmit(self.state, buf)

        return super(transmit, self).run(fd, buf, count, tx_bytes)

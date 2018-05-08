import logging

from ..cgc.receive import receive as orig_receive


l = logging.getLogger("angr.procedures.tracer.receive")


class receive(orig_receive):
    # pylint:disable=arguments-differ
    """
    Receive which fixes the input to file descriptor to 0.
    """

    def run(self, fd, buf, count, rx_bytes):
        if len(self.state.se.eval_upto(fd, 2)) < 2:
            if self.state.se.eval(fd) == 1:
                l.debug("Fixed receive call's fd.")
                fd = self.state.se.BVV(0, self.state.arch.bits)

        return super(receive, self).run(fd, buf, count, rx_bytes)

import logging

from ..cgc.receive import receive as orig_receive


l = logging.getLogger(name=__name__)


class receive(orig_receive):
    # pylint:disable=arguments-differ
    """
    Receive which fixes the input to file descriptor to 0.
    """

    def run(self, fd, buf, count, rx_bytes):
        if len(self.state.solver.eval_upto(fd, 2)) < 2:
            if self.state.solver.eval(fd) == 1:
                l.debug("Fixed receive call's fd.")
                fd = self.state.solver.BVV(0, self.state.arch.bits)

        return super().run(fd, buf, count, rx_bytes)

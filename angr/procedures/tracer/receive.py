import logging

from ..cgc.receive import receive as orig_receive


l = logging.getLogger("angr.procedures.tracer.receive")


def cache_pass(_):
    l.warning("cache_hook never set")


# called when caching the state
cache_hook = cache_pass


class receive(orig_receive):
    # pylint:disable=arguments-differ
    """
    Receive which fixes the input to file descriptor to 0.
    """

    def run(self, fd, buf, count, rx_bytes):
        if self.state.se.eval(self.state.posix.files[0].pos) == 0:
            if cache_hook is not None:
                cache_hook(self.state)

        if self.state.se.eval_upto(fd, 2) < 2:
            if self.state.se.eval(fd) == 1:
                l.debug("Fixed receive call's fd.")
                fd = self.state.se.BVV(0, self.state.arch.bits)

        return super(receive, self).run(fd, buf, count, rx_bytes)

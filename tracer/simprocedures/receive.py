from simuvex.procedures.cgc.receive import receive

import logging
l = logging.getLogger("tracer.simprocedures.FixedInReceive")

def cache_pass(_):
    l.warning("cache_hook never set")

# called when caching the state
cache_hook = cache_pass

class FixedInReceive(receive):
    # pylint:disable=arguments-differ
    """
    Receive which fixes the input to file descriptor to 0.
    """

    def run(self, fd, buf, count, rx_bytes):

        if self.state.se.any_int(self.state.posix.files[0].pos) == 0:
            if cache_hook is not None:
                cache_hook(self.state)

        if self.state.se.any_n_int(fd, 2) < 2:
            if self.state.se.any_int(fd) == 1:
                l.debug("fixed receive call's fd")
                fd = self.state.se.BVV(0, self.state.arch.bits)

        return super(FixedInReceive, self).run(fd, buf, count, rx_bytes)

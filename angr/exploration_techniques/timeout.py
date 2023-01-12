import time
import logging
from . import ExplorationTechnique

l = logging.getLogger(name=__name__)


class Timeout(ExplorationTechnique):
    """
    Timeout exploration technique that stops an active exploration if the run time exceeds
    a predefined timeout
    """

    def __init__(self, timeout=None):
        super().__init__()
        self.start_time = None
        self.timeout = timeout

    def setup(self, simgr):
        simgr.stashes["timeout"] = []

    def step(self, simgr, stash="active", **kwargs):
        if self.start_time is None:
            self.start_time = time.time()
        if self.timeout is not None and time.time() - self.start_time > self.timeout:
            self.start_time = None
            simgr.move(stash, "timeout")
            l.warning("exploration timeout in %s seconds!", self.timeout)
        else:
            simgr = simgr.step(stash=stash, **kwargs)
        return simgr

#from ..analysis import Analysis
#from ..variableseekr import StackVariable
from sleak import SleakMeta
from ..surveyors import Explorer
import logging

l = logging.getLogger("analysis.xsleak")

class XSleak(SleakMeta):
    """
    Stack leak detection based on Explorer (i.e., full symbolic execution).
    We identify stuff that look like addresses at runtime, and start tracking
    them from there, until we reach targets.
    """

    def __init__(self, mode=None, targets=None, iexit=None):
        self.prepare(iexit=iexit)

    def terminated_paths(self):
        return self.xpl.found

    def run(self, keep_going = False):
        """
        Run the analysis.
        If keep_going is False (default), then we stop after we found a satisfying path.
        Otherwise, we keep going until there are no active paths left.
        """
        # Explorer wants a tuple of addresses
        find_addrs = tuple(self.targets.values())

        self.xpl = Explorer(self._p, find=find_addrs, start=self.iexit)

        # Keep going while we have active paths
        while len(self.xpl.active) > 0:
            self.xpl.step()
            if keep_going == False and len(self.xpl.found) > 0:
                break

        # Debug the address tracking hooks
        if self.mode == "track_addr":
            if len(self.tracked) == 0:
                l.debug("No stack addresses was found X(")
            else:
                l.debug("Found %s" % repr(self.tracked))

        # Results
        if len(self.xpl.found) == 0:
            l.error("I didn't find anyting :(")
        else:
            l.info("Reached %s" % repr(self.xpl.found))

#from ..analysis import Analysis
#from ..variableseekr import StackVariable
from sleak import Sleak
from ..surveyors import Explorer
from ..errors import AngrAnalysisError
import logging
import simuvex

l = logging.getLogger("analysis.xsleak")

class XSleak(Sleak):
    """
    Stack leak detection based on Explorer (i.e., full symbolic execution).
    We identify stuff that look like addresses at runtime, and start tracking
    them from there, until we reach targets.
    """

    def __init__(self, mode=None, targets=None):
        """
        Explore the binary until targets are found.
        @targets: a tuple of manually identified targets.
        If @targets is none, we try to identify targets automatically.
        @mode:
            - "track_sp": make the stack pointer symbolic and track everything that depends on it.
            - "track_addr": Stuff concretizable to addresses is tracked.

        """
        self.targets = self.find_targets() if targets is None else targets

        if self.targets is None:
            raise AngrAnalysisError("No targets found and none defined!")
            return

        if mode is None or mode == "track_sp":
            self.mode = "track_sp"
        elif mode == "track_addr":
            self.mode = "track_addr"
        else:
            raise AngrAnalysisError("Invalid mode")

        self.stack_bottom = self._p.arch.initial_sp
        l.debug("Stack bottom is at 0x%x" % self.stack_bottom)
        self.stack_top = None
        self.tracked = []

        self.iexit = self._p.initial_exit()

        if self.mode == "track_sp":
            #self.iexit.state.inspect.add_breakpoint('reg_write',
            #                                        simuvex.BP(simuvex.BP_AFTER,
            #                                                   action=self.make_sp_symbolic))
            self.iexit.state.inspect.add_breakpoint('reg_read',
                                                    simuvex.BP(simuvex.BP_BEFORE,
                                                               action=self.make_sp_symbolic))
        else:
            # Look for all memory writes
            self.iexit.state.inspect.add_breakpoint(
                'mem_write', simuvex.BP(simuvex.BP_AFTER, action=self.track_mem_write))

            # Make sure the stack pointer is symbolic before we read it
            self.iexit.state.inspect.add_breakpoint(
                'mem_read', simuvex.BP(simuvex.BP_AFTER, action=self.track_mem_read))


    def run(self, keep_going = False):
        """
        Run the analysis.
        If keep_going is False (default), then we stop after we found a satisfying path.
        Otherwise, we keep going until there are no active paths left.
        """
        self.xpl = Explorer(self._p, find=self.targets, start=self.iexit)

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
            return

        l.info("%d matching paths found" % len(self.xpl.found))
        for fo in self.xpl.found:
            ex = fo.exits()
            l.info("Path with %d exits" % len(ex))
            for e in ex:
                self.check_parameters(e.state)




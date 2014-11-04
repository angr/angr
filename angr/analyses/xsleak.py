from ..analysis import Analysis
#from ..variableseekr import StackVariable
from ..surveyors import Explorer
import logging

l = logging.getLogger("analyses.XSleak")

class XSleak(Analysis):
    """
    Stack leak detection based on Explorer (i.e., full symbolic execution)
    """

    def __init__(self, targets=None):
        """
        Explore the binary until targets are found.
        @targets: a tuple of manually identified targets.
        If @targets is none, we try to identify targets automatically.
        """

        self.iexit = self._p.initial_exit()
        self.targets = self.find_targets() if targets is None else targets

        if targets is None:
            l.error("No targets.")

    def find_targets(self):
        """
        What are the target addresses we are interested in ?
        These are output or interface functions.
        """
        # TODO

    def make_symbolic(self, addr, size, name):
        #self.slicecutor._project.initial_exit().state.memory.make_symbolic(addr, size, name)
        self.iexit.state.memory.make_symbolic(addr, size, name)

    def run(self):
        self.xpl = Explorer(self._p, find=self.targets, start=self.iexit)
        return self.xpl

    def reginfo(self, reg):
        if (self.state is None):
            raise Exception("You need to run the slice first !")

        const = self.end_state.se.simplify(self.end_state.reg_expr(reg))
        #c = claripy.solvers.CompositeSolver()

        mi = self.end_state.se.min_expr(const)
        ma = self.end_state.se.max_expr(const)

        print " --- Reg %s ---" % reg
        print "\t Min: %s - Max: %s" % (mi, ma)
        print "\t Constraints: %s" % const
        print "---"


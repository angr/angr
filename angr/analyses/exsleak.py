from ..analysis import Analysis
from ..variableseekr import StackVariable
from ..surveyors import Slicecutor
import logging

l = logging.getLogger("Sleak")

class ExSleak(Analysis):
    """
    Stack leak detection based on Explorer (i.e., full symbolic execution)
    """

    def __init__(self):
        """

        """
        self.init_exit = self._p.initial_exit()

        self.find_targets()

        self.xpl = Explorer(self._p, find=self.targets)


    def find_targets(self):
        """
        What are the target addresses we are interested in ?
        These are output or interface functions.
        """

        # TODO
        self.targets = (0x40056e)

    def make_symbolic(self, addr, size, name):
        #self.slicecutor._project.initial_exit().state.memory.make_symbolic(addr, size, name)
        self.init_exit.state.memory.make_symbolic(addr, size, name)

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


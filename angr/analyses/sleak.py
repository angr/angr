from ..analysis import Analysis
from ..variableseekr import StackVariable
from ..surveyors import Slicecutor
import logging

l = logging.getLogger("Sleak")
class Sleak(Analysis):
    """
    Stack leak detection, slices through the program towards identified output
    functions.

    """

    __name__ = "LS"
    __dependencies__ = [ 'CFG' ]

    def __init__(self, mode = "slice"):
        """
        @mode: whether we execute a slice or everything. Valid modes: slice and
        full
        @target_addr: which block are we targeting ?
        """

        self.init_state = self._p.initial_state()

    def make_symbolic(self, addr, size, name):
        #self.slicecutor._project.initial_exit().state.memory.make_symbolic(addr, size, name)
        self.init_state.memory.make_symbolic(addr, size, name)

    def run(self, target_addr, target_stmt = None, begin = None):
        """
        @begin: where to start ? The default is the entry point of the program
        @target_addr: address of the destination's basic block
        @target_stmt: id of the VEX statement in that block
        """
        #target_irsb = self.proj._cfg.get_any_irsb(target_addr)

        if begin is None:
            begin = self._p.entry

        s = self._p.slice_to(target_addr, begin, target_stmt)
        self.slicecutor = Slicecutor(self._p, s) #, start = self.init_state)
        self.slicecutor.run()

        self.path = self.slicecutor.deadended[0] # There may be more here
        self.last = self.path.last_run

        #def_exit = last.default_exit
       # target = def_exit.target
       # print "Default exit target of reached block: %s" % hex(def_exit.state.se.any_int(target))

        self.end_state = self.last.default_exit.state

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


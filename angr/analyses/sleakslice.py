from ..surveyors import Slicecutor
from sleak import SleakMeta
import logging

l = logging.getLogger("analysis.sleakslice")

class Sleakslice(SleakMeta):
    """
    Stack leak detection, slices through the program towards identified output
    functions.

    """

    def __init__(self, iexit=None, targets=None):
        self.prepare(iexit=iexit)
        self.slices = []
        self.found_exits = []

    def run(self):
        self.cfg = self._p.analyses.CFG()
        for t in self.targets.values():
            l.debug("Running slice towards 0x%x" % t)
            #with self._resilience():
            r = self._run_slice(t)
            self.slices.append(r)

    def terminated_paths(self):
        """
        Where did the analysis stop ?
        """
        paths=[]
        for sl in self.slices:
            paths = paths + sl.deadended + sl.cut
        return paths

    def _run_slice(self, target_addr, target_stmt = None, begin = None):
        """
        @begin: where to start ? The default is the entry point of the program
        @target_addr: address of the destination's basic block
        @target_stmt: idx of the VEX statement in that block
        """
        #target_irsb = self.proj._cfg.get_any_irsb(target_addr)

        if begin is None:
            begin = self._p.entry

        #s = self._p.slice_to(target_addr, begin, target_stmt)

        a = self._p.analyses.AnnoCFG(target_addr, stmt_idx=target_stmt,
                                start_addr=begin)

        slicecutor = Slicecutor(self._p, a.annocfg, start=self.iexit) #, start = self.init_state)
        slicecutor.run()
        return slicecutor

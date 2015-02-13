from ..surveyors import Slicecutor
from sleak import SleakMeta
from angr.errors import AngrExitError
#from angr.annocfg import AnnotatedCFG
import logging

l = logging.getLogger("analysis.sleakslice")

class Sleakslice(SleakMeta):
    """
    Stack leak detection, slices through the program towards identified output
    functions.

    """

    def __init__(self, istate=None, targets=None, mode=None, argc=None):
        """
        @istate: an initial state to use
        @targets: a {function_name:address} dict of targets to look for
        @argc: how many symbolic arguments ?
        """

        self.cfg = self._p.analyses.CFG()
        self.prepare(istate=istate, targets=targets, mode=mode, argc=argc)
        self.slices = []
        self.failed_targets = [] # Targets outside the CFG
        #self.found_paths = []
        self.run()

    def run(self):
        for t in self.targets.values():
            l.debug("Running slice towards 0x%x" % t)
            #with self._resilience():
            try:
                r = self._run_slice(target_addr = t)
            except AngrExitError as error:  # not in the CFG
                self.failed_targets.append(t)
                l.debug(error)
                l.info("Skipping target 0x%x (%s)" % (t, self.target_name(t)))
                continue

            self.slices.append(r)
            self._check_found_paths()

    @property
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
            #begin = self._p.entry
            begin = self.ipath.addr

        #s = self._p.slice_to(target_addr, begin, target_stmt)

        #a_cfg = AnnotatedCFG(self._p, self.cfg, target_addr)
        #slicecutor = Slicecutor(self._p, a_cfg, start=self.iexit) #, start = self.init_state)

        a = self._p.analyses.AnnoCFG(target_addr, stmt_idx=target_stmt,
                                start_addr=begin)

        slicecutor = Slicecutor(self._p, a.annocfg, start=self.ipath, targets=[target_addr]) #, start = self.init_state)
        slicecutor.run()
        return slicecutor

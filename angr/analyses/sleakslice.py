from ..surveyors import Slicecutor
from sleak import SleakMeta
import logging

l = logging.getLogger("analysis.sleakslice")
class Sleakslice(SleakMeta):
    """
    Stack leak detection, slices through the program towards identified output
    functions.

    """

    __dependencies__ = [ 'CFG', 'CDG' ]

    def __init__(self, initial_state=None, targets=None):
        self.prepare()
        self.slices = []
        self.found_exits = []

    def run(self):
        for t in self.targets:
            l.debug("Running slice towards 0x%x" % t)
            r = self._run_slice(t)
            self.slices.append(r)

        for sl in self.slices:
            self._check_paths(sl)

    def _check_paths(self, slice):
        # TODO: use arch info instead
        regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        paths = slice.deadended + slice.cut
        for path in paths:
            last_run = path.last_run
            if last_run.addr in self.targets:
                l.info("Target reached")
            for ex in last_run.exits():
                for reg in regs:
                    exp = ex.state.reg_expr(reg)
                    if "STACK_TRACK" in repr(exp):
                        l.info("Found a matching exit at 0x%x" % ex.concretize())
                        if ex.concretize() not in self.targets:
                            l.warning("\t ->exit not in targets")
                        self.found_exits.append(ex)

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

        a = self._p.analyze("AnnoCFG", target_addr, stmt_idx=target_stmt,
                                start_addr=begin)

        slicecutor = Slicecutor(self._p, a.annocfg, start=self.iexit) #, start = self.init_state)
        slicecutor.run()
        return slicecutor

        #self.path = self.slicecutor.deadended[0] # There may be more here
        #self.last = self.path.last_run

        #def_exit = last.default_exit
        # target = def_exit.target
        # print "Default exit target of reached block: %s" % hex(def_exit.state.se.any_int(target))

        #self.end_state = self.last.default_exit.state


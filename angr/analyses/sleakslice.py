from ..surveyors import Slicecutor
from ..analysis import register_analysis
from sleak import SleakMeta, SleakError
from angr.errors import AngrExitError
import logging

l = logging.getLogger("analysis.sleakslice")

class Sleakslice(SleakMeta):
    """
    Stack leak detection, slices through the program towards identified output
    functions.

    """

    def __init__(self, istate=None, mode=None, argc=None):
        """
        @istate: an initial state to use
        @targets: a list of target addrs to look for
        @argc: how many symbolic arguments ?
        """

        self.prepare(istate=istate, mode=mode, argc=argc)
        self.slices = []
        self.failed_targets = [] # Targets outside the CFG
        #self.found_paths = []

        #self.run()

    def run(self):

        if len(self.targets) == 0:
            raise SleakError("No targets specified")

        self.cfg = self.project.analyses.CFG(keep_input_state=True)
        self.ddg = self.project.analyses.DDG(cfg=self.cfg)
        self.cdg = self.project.analyses.CDG(cfg=self.cfg)

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

            self.slices = self.slices + r
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

    def _run_slice(self, target_addr, target_stmt = -1, begin = None):
        """
        @begin: where to start ? The default is the entry point of the program
        @target_addr: address of the destination's basic block
        @target_stmt: idx of the VEX statement in that block
        """

        target_nodes = self.cfg.get_all_nodes(target_addr)
        slices=[]

        # We create a slice per target_irsb for a given target
        for target in target_nodes:
            if target is None:
                raise AngrExitError("The CFG doesn't contain any node at "
                                    "0x%x" % target_addr)

            if begin is None:
                begin = self.ipath.addr

            bwslice = self.project.analyses.BackwardSlice(self.cfg, self.cdg, self.ddg,
                                                    target, target_stmt,
                                                    control_flow_slice=False)

            self.annocfg = bwslice.annotated_cfg(start_point=self.ipath.addr)
            slicecutor = Slicecutor(self.project, self.annocfg, start=self.ipath,
                                    targets=[target_addr])
            slicecutor.run()
            slices.append(slicecutor)
        return slices

    def _check_found_paths(self):
        """
        Iterates over all found paths to identify leaking ones
        """
        results = []
        if len(self.found_paths) > 0:
            self.reached_target = True

        # Found paths : output function reached
        for p in self.found_paths:
            r = self._check_path(p)
            if r is not None:
                results.append(r)
        self.leaks = results

register_analysis(Sleakslice, 'Sleakslice')

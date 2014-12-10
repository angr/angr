from ..analysis import Analysis
#from ..annocfg import AnnotatedCFG
from ..sliceinfo import SliceInfo
from ..errors import AngrExitError

class AnnoCFGAnalysis(Analysis):
    __analysis_name__ = 'AnnoCFG'

    def __init__(self, addr, stmt_idx=None, start_addr=None, avoid_runs=None, cfg_only=True):
            """
            Creates an annotated CFG corresponding to a program slice from @start_addr to @addr
            Note that @addr must be a valid IRSB in the CFG
            """

            self._cfg = self._p.results.CFG
            self._cdg = self._p.results.CDG

            s = SliceInfo(self._p.main_binary, self._p, self._cfg, self._cdg, None)
            target_irsb = self._cfg.get_any_irsb(addr)

            if target_irsb is None:
                raise AngrExitError("The CFG doesn't contain any IRSB starting at "
                                    "0x%x" % addr)


            target_stmt = -1 if stmt_idx is None else stmt_idx
            s.construct(target_irsb, target_stmt, control_flow_slice=cfg_only)
            self.annocfg = s.annotated_cfg(addr, start_point=start_addr, target_stmt=target_stmt)

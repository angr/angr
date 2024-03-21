import logging

import networkx

from .return_duplicator_base import ReturnDuplicatorBase
from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class ReturnDuplicatorHigh(OptimizationPass, ReturnDuplicatorBase):
    """
    Does a more conservative version of the ReturnDuplicatorLow optimization pass.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.DURING_REGION_IDENTIFICATION
    NAME = "Duplicate return-only blocks (high)"
    DESCRIPTION = __doc__  # pylint:disable=unsubscriptable-object

    def __init__(
        self,
        func,
        # internal parameters that should be used by Clinic
        node_idx_start: int = 0,
        # settings
        max_calls_in_regions: int = 2,
        minimize_copies_for_regions: bool = True,
        **kwargs,
    ):
        ReturnDuplicatorBase.__init__(
            self,
            func,
            node_idx_start=node_idx_start,
            max_calls_in_regions=max_calls_in_regions,
            minimize_copies_for_regions=minimize_copies_for_regions,
            **kwargs,
        )
        OptimizationPass.__init__(self, func, **kwargs)
        self.analyze()

    def _check(self):
        return ReturnDuplicatorBase._check(self)

    def _should_duplicate_dst(self, src, dst, graph, dst_is_const_ret=False):
        # TODO: implement a better check
        return dst_is_const_ret

    def _analyze(self, cache=None):
        copy_graph = networkx.DiGraph(self._graph)
        if self._analyze_core(copy_graph):
            self.out_graph = self._simplify_graph(copy_graph)

from __future__ import annotations
import logging
from typing import Any

import networkx

from .return_duplicator_base import ReturnDuplicatorBase
from .optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.structuring import SAILRStructurer, DreamStructurer

_l = logging.getLogger(name=__name__)


class ReturnDuplicatorHigh(OptimizationPass, ReturnDuplicatorBase):
    """
    This is a light-level goto-less version of the ReturnDuplicator optimization pass. It will only
    duplicate return-only blocks.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Duplicate return-only blocks (high)"
    DESCRIPTION = __doc__
    STRUCTURING = [SAILRStructurer.NAME, DreamStructurer.NAME]

    def __init__(
        self,
        func,
        # settings
        max_calls_in_regions: int = 2,
        minimize_copies_for_regions: bool = True,
        region_identifier=None,
        vvar_id_start: int | None = None,
        scratch: dict[str, Any] | None = None,
        **kwargs,
    ):
        OptimizationPass.__init__(
            self, func, vvar_id_start=vvar_id_start, scratch=scratch, region_identifier=region_identifier, **kwargs
        )
        ReturnDuplicatorBase.__init__(
            self,
            func,
            max_calls_in_regions=max_calls_in_regions,
            minimize_copies_for_regions=minimize_copies_for_regions,
            ri=region_identifier,
            vvar_id_start=vvar_id_start,
            scratch=scratch,
        )
        # since we run before the RegionIdentification pass in the decompiler, we need to collect it early here
        self._ri = self._recover_regions(self._graph)

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

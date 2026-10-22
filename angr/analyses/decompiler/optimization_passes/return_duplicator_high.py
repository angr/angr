from __future__ import annotations

import logging
from typing import Any

from angr.analyses.decompiler.structuring import DreamStructurer, SAILRStructurer
from angr.analyses.decompiler.utils import copy_graph

from .optimization_pass import OptimizationPass, OptimizationPassStage
from .return_duplicator_base import ReturnDuplicatorBase

_l = logging.getLogger(name=__name__)


class ReturnDuplicatorHigh(OptimizationPass, ReturnDuplicatorBase):
    """
    This is a light-level goto-less version of the ReturnDuplicator optimization pass. It will only
    duplicate return-only blocks.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Duplicate return-only blocks (high)"
    DESCRIPTION = __doc__ or ""
    STRUCTURING = [SAILRStructurer.NAME, DreamStructurer.NAME]

    def __init__(
        self,
        *args,
        # settings
        vvar_id_start: int,
        max_calls_in_regions: int = 2,
        minimize_copies_for_regions: bool = True,
        scratch: dict[str, Any] | None = None,
        **kwargs,
    ):
        OptimizationPass.__init__(self, *args, vvar_id_start=vvar_id_start, scratch=scratch, **kwargs)
        ReturnDuplicatorBase.__init__(
            self,
            *args,
            max_calls_in_regions=max_calls_in_regions,
            minimize_copies_for_regions=minimize_copies_for_regions,
            vvar_id_start=vvar_id_start,
            scratch=scratch,
        )

        self.analyze()

    def _check(self):
        return ReturnDuplicatorBase._check(self)

    def _should_duplicate_dst(self, src, dst, graph, dst_is_const_ret=False):
        # TODO: implement a better check
        return dst_is_const_ret

    def _region_identifier(self, graph):
        # we run before the decompiler's region identification, and most functions never need the regions (no
        # end-node region has a multi-node predecessor component), so they are recovered on first use
        if self._ri is None:
            self._ri = self._recover_regions(graph)
        return self._ri

    def _analyze(self, cache=None):
        graph_copy = copy_graph(self._graph)
        if self._analyze_core(graph_copy):
            self.out_graph = self._simplify_graph(graph_copy)

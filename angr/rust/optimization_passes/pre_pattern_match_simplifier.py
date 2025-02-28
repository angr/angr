from __future__ import annotations
import logging
from typing import Any

import networkx
from ailment.statement import ConditionalJump

from angr.analyses.decompiler.structuring import SAILRStructurer, DreamStructurer
from angr.analyses.decompiler.optimization_passes.return_duplicator_base import ReturnDuplicatorBase
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class PrePatternMatchSimplifier(OptimizationPass, ReturnDuplicatorBase):
    """
    Duplicate return blocks for identified pattern matches to form if-else structures.
    For example the following code,
        ```
        if (...){
            ...
        } else {
            v6 = std::fs::File::open(a1, a2);
            if !v6 as i32 {
                ...
            }
        }
        return Err(struct8 {
            field_0: v11
        });
        ```
    should be converted to
        ```
        v6 = std::fs::File::open(a1, a2);
        if v6 as i32 {
            return Err(struct8 {
                field_0: v11
            });
        } else {
            ...
        }
        ```
    for recovering pattern match constructs in later stage
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.RUST_SPECIFIC_SIMPLIFICATION
    NAME = "Duplicate return blocks to prepare for pattern match simplification"
    DESCRIPTION = __doc__
    STRUCTURING = [SAILRStructurer.NAME, DreamStructurer.NAME]

    def __init__(
        self,
        func,
        # settings
        *,
        vvar_id_start: int,
        max_calls_in_regions: int = 2,
        minimize_copies_for_regions: bool = True,
        scratch: dict[str, Any] | None = None,
        **kwargs,
    ):
        OptimizationPass.__init__(self, func, vvar_id_start=vvar_id_start, scratch=scratch, **kwargs)
        ReturnDuplicatorBase.__init__(
            self,
            func,
            max_calls_in_regions=max_calls_in_regions,
            minimize_copies_for_regions=minimize_copies_for_regions,
            vvar_id_start=vvar_id_start,
            scratch=scratch,
        )

        self.analyze()

    def _check(self):
        return bool(self._func.endpoints) and self.project.is_rust_binary, None

    def _should_duplicate_dst(self, src, dst, graph, dst_is_const_ret=False):
        pred = next(graph.predecessors(src), None)
        if pred and pred.statements and isinstance(pred.statements[-1], ConditionalJump):
            jump = pred.statements[-1]
            return "scrutinee" in jump.condition.tags
        return False

    def _analyze(self, cache=None):
        # since we run before the RegionIdentification pass in the decompiler, we need to collect it early here
        self._ri = self._recover_regions(self._graph)
        copy_graph = networkx.DiGraph(self._graph)
        if self._analyze_core(copy_graph):
            self.out_graph = self._simplify_graph(copy_graph)

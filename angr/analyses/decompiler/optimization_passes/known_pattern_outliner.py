from __future__ import annotations

import logging

from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(__name__)


class KnownPatternOutliner(OptimizationPass):
    """
    Automatically finds occurrences of KnownPatterns (inlined library idioms
    such as std::string::length() or std::vector<int>::size(); see
    angr.analyses.decompiler.known_patterns) in the AIL graph and outlines them
    into calls via the KnownPatternFinder analysis.

    Runs right before variable recovery so that the synthesized calls' argument
    types flow into Typehoon within the same decompilation run.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Outline known code patterns into calls"
    DESCRIPTION = __doc__.strip()

    MAX_ROUNDS = 8

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        from angr.analyses.decompiler.known_patterns import (  # pylint:disable=import-outside-toplevel
            PatternContext,
            patterns_for,
        )

        ctx = PatternContext.from_project(self.project)
        return bool(patterns_for(ctx, enabled_only=True)), None

    def _analyze(self, cache=None):
        from angr.analyses.decompiler.known_patterns import (  # pylint:disable=import-outside-toplevel
            KnownPatternFinder,
            UnsupportedOutlineError,
        )
        from angr.analyses.decompiler.known_patterns.apply import (  # pylint:disable=import-outside-toplevel
            apply_call_info_to_graph,
        )

        graph = self._graph
        block_addr_start = self.new_block_addr()
        changed = False

        for _ in range(self.MAX_ROUNDS):
            finder = self.project.analyses[KnownPatternFinder].prep(kb=self.kb)(
                self._func,
                graph,
                vvar_id_start=max(self.vvar_id_start, 1),
                block_addr_start=block_addr_start,
                ail_manager=self.manager,
            )
            if not finder.matches:
                break
            progressed = False
            for match in finder.matches:
                try:
                    result = finder.outline(match, ail_graph=graph)
                except UnsupportedOutlineError as ex:
                    _l.debug("Cannot outline %r: %s", match, ex)
                    continue
                graph = result.graph
                progressed = True
                changed = True
            self.vvar_id_start = finder.vvar_id_start
            block_addr_start = finder.block_addr_start
            self._new_block_addrs.add(block_addr_start)
            if not progressed:
                break

        if changed:
            # peepholes have already run by this stage, so the prototypes of the
            # newly synthesized calls must be applied here for this run
            apply_call_info_to_graph(graph, self.manager, self.project)
            self.out_graph = graph

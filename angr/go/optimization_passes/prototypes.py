from __future__ import annotations

import logging

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.calling_conventions import GO_ABI0_CC, default_cc_for_project
from angr.go.utils.names import call_target_name
from angr.knowledge_plugins.functions.function import Function, PrototypeSource
from angr.rust.utils.ail import CallFinder

l = logging.getLogger(__name__)

# prototypes from signatures beat everything the decompiler infers, but never a user-supplied one
_SOURCE = PrototypeSource.SIGNATURES


class GoPrototypes(OptimizationPass):
    """
    Give the current function and its callees their Go prototypes (from DWARF, the stdlib signature database or an
    external source registered on kb.go_signatures) before return sites, argument lists and call sites are built.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_AIL_GRAPH_CREATION
    NAME = "Apply known Go prototypes"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        self.kb.go_signatures.load_sources()

        self._apply(self._func)

        finder = CallFinder()
        seen: set[int] = set()
        for block in self._graph.nodes:
            for stmt in block.statements:
                finder.call = None
                finder.walk_statement(stmt, block)
                call = finder.call
                if call is None:
                    continue
                name = call_target_name(self.project, call)
                if name is None or not self.kb.functions.contains_addr(call.target.value_int):
                    continue
                callee = self.kb.functions.get_by_addr(call.target.value_int)
                if callee.addr in seen:
                    continue
                seen.add(callee.addr)
                self._apply(callee)

    def _apply(self, func: Function) -> bool:
        if func.prototype is not None and func.prototype_source.value > _SOURCE.value:
            return False
        proto = self.kb.go_signatures.prototype(func.name)
        if proto is None:
            return False
        cc_cls = (
            GO_ABI0_CC.get(self.project.arch.name)
            if func.name.endswith(".abi0")
            else default_cc_for_project(self.project)
        )
        if cc_cls is None:
            return False
        if func.calling_convention is None or not isinstance(func.calling_convention, cc_cls):
            func.calling_convention = cc_cls(self.project.arch)
        func.prototype = proto
        func.prototype_source = _SOURCE
        l.debug("Applied Go prototype to %s: %s", func.name, proto.repr(func.name))
        return True

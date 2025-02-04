from __future__ import annotations
from typing import TYPE_CHECKING, cast

from collections.abc import Iterator
from dataclasses import dataclass
import logging

from angr.project import Project
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.key_definitions import DerefSize
from angr.knowledge_plugins.key_definitions.constants import ObservationPointType
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.sim_variable import SimMemoryVariable

if TYPE_CHECKING:
    from angr.analyses.reaching_definitions import (
        ReachingDefinitionsAnalysis,
        FunctionCallRelationships,
    )


log = logging.getLogger(__name__)


@dataclass
class APIObfuscationType2:
    """
    API Obfuscation Type 2 result.
    """

    resolved_func_name: str
    resolved_func_ptr: MemoryLocation
    resolved_in: Function
    resolved_by: Function


class APIObfuscationType2Finder:
    """
    Finds global function pointers initialized by calls to dlsym/GetProcAddress and names
    them accordingly.
    """

    results: list[APIObfuscationType2]

    def __init__(self, project: Project, variable_kb: KnowledgeBase | None = None):
        self.project = project
        self.variable_kb = variable_kb or self.project.kb
        self.results = []

    def analyze(self) -> list[APIObfuscationType2]:
        self.results = []
        for caller, callee in self._get_candidates():
            rda = self.project.analyses.ReachingDefinitions(caller, observe_all=True)
            for info in rda.callsites_to(callee):
                self._process_callsite(caller, callee, rda, info)
        self._mark_globals()
        return self.results

    def _get_candidates(self) -> Iterator[tuple[Function, Function]]:
        """
        Returns a tuple of (caller, callee) where callee is GetProcAddress/dlsym.
        """
        targets = ["GetProcAddress"] if self.project.simos.name == "Win32" else ["dlsym", "dlvsym"]
        for callee in self.project.kb.functions.values():
            if callee.name not in targets:
                continue
            for caller_addr in self.project.kb.callgraph.predecessors(callee.addr):
                caller = self.project.kb.functions[caller_addr]
                yield (caller, callee)

    def _process_callsite(
        self,
        caller: Function,
        callee: Function,
        rda: ReachingDefinitionsAnalysis,
        callsite_info: FunctionCallRelationships,
    ) -> None:
        """
        Process a resolver function callsite looking for function name concrete string argument.
        """
        func_name_arg_idx = 1
        if len(callsite_info.args_defns) <= func_name_arg_idx:
            return

        log.debug("Examining call to %r from %r at %r", callee, caller, callsite_info.callsite.ins_addr)
        ld = rda.model.get_observation_by_insn(callsite_info.callsite, ObservationPointType.OP_BEFORE)
        if ld is None:
            return

        # Attempt resolving static function name from callsite
        string_atom = ld.deref(callsite_info.args_defns[func_name_arg_idx], DerefSize.NULL_TERMINATE)
        result = ld.get_concrete_value(string_atom, cast_to=bytes)
        if result is None:
            log.debug("...Failed to resolve a function name")
            return

        try:
            func_name = result.rstrip(b"\x00").decode("utf-8")
            log.debug("...Resolved concrete function name: %s", func_name)
        except UnicodeDecodeError:
            log.debug("...Failed to decode utf-8 function name")
            return

        # Examine successor definitions to find where the function pointer is written
        for successor in rda.dep_graph.find_all_successors(callsite_info.ret_defns):
            if not (
                isinstance(successor.atom, MemoryLocation)
                and isinstance(successor.atom.addr, int)
                and successor.atom.size == self.project.arch.bytes
            ):
                continue

            ptr = successor.atom
            ptr_addr: int = cast(int, ptr.addr)
            log.debug("...Found function pointer %r", ptr)

            sym = self.project.loader.find_symbol(ptr_addr)
            if sym is not None:
                log.debug("...Already have pointer symbol: %r. Skipping.", sym)
                continue
            if ptr_addr in self.project.kb.labels:
                log.debug("...Already have pointer label. Skipping.")
                continue
            sec = self.project.loader.find_section_containing(ptr_addr)
            if not sec or not sec.is_writable:
                log.debug("...Bogus section. Skipping.")
                continue

            self.results.append(
                APIObfuscationType2(
                    resolved_func_name=func_name,
                    resolved_func_ptr=ptr,
                    resolved_in=caller,
                    resolved_by=callee,
                )
            )

    def _mark_globals(self):
        """
        Create function pointer labels/variables.
        """
        for result in self.results:
            # Create a label
            lbl = self.project.kb.labels.get_unique_label(f"p_{result.resolved_func_name}")
            self.project.kb.labels[result.resolved_func_ptr.addr] = lbl
            log.debug("...Created label %s for address %x", lbl, result.resolved_func_ptr.addr)

            # Create a variable
            global_variables = self.variable_kb.variables["global"]
            variables = global_variables.get_global_variables(result.resolved_func_ptr.addr)
            if not variables:
                ident = global_variables.next_variable_ident("global")
                var = SimMemoryVariable(
                    result.resolved_func_ptr.addr, result.resolved_func_ptr.size, name=lbl, ident=ident
                )
                global_variables.set_variable("global", result.resolved_func_ptr.addr, var)
                log.debug("...Created variable %r", var)
            elif len(variables) == 1:
                (var,) = variables
                log.debug("...Renaming variable %r -> %s", var, lbl)
                var.name = lbl

            self.project.kb.obfuscations.type2_deobfuscated_apis[result.resolved_func_ptr.addr] = (
                result.resolved_func_name
            )

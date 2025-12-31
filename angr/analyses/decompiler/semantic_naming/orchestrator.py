# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Orchestrator for semantic variable naming patterns.

This module coordinates multiple naming patterns and applies them in priority order.

Note: Loop counter naming is NOT included here as it runs in RegionSimplifier
after structuring, where it can leverage the structured LoopNode information.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

import networkx

from angr import ailment
from angr.sim_variable import SimVariable
from .naming_base import ClinicNamingBase
from .array_index_naming import ArrayIndexNaming
from .call_result_naming import CallResultNaming
from .size_naming import SizeNaming
from .boolean_naming import BooleanNaming
from .pointer_naming import PointerNaming

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions.function_manager import FunctionManager
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

l = logging.getLogger(name=__name__)

# All available naming patterns that run in Clinic, will be sorted by priority
# Note: LoopCounterNaming is NOT included here - it runs in RegionSimplifier
# after structuring to leverage the structured LoopNode information.
NAMING_PATTERNS: list[type[ClinicNamingBase]] = [
    PointerNaming,
    ArrayIndexNaming,
    CallResultNaming,
    SizeNaming,
    BooleanNaming,
]


class SemanticNamingOrchestrator:
    """
    Orchestrates multiple semantic naming patterns.

    Runs each pattern in priority order (lower PRIORITY value = runs first).
    Variables named by higher-priority patterns are not renamed by lower-priority ones.
    """

    def __init__(
        self,
        ail_graph: networkx.DiGraph,
        variable_manager: VariableManagerInternal,
        functions: FunctionManager,
        entry_node: ailment.Block,
        patterns: list[type[ClinicNamingBase]] | None = None,
    ):
        self._graph = ail_graph
        self._variable_manager = variable_manager
        self._functions = functions
        self._entry_node = entry_node
        self._patterns = patterns or NAMING_PATTERNS

        # Track all renamed variables
        self.renamed_variables: set[SimVariable] = set()
        self.variable_patterns: dict[SimVariable, str] = {}

    def analyze(self) -> dict[SimVariable, str]:
        """
        Run all semantic naming patterns in priority order.

        :return: Combined mapping of all renamed variables to their new names
        """
        all_renames: dict[SimVariable, str] = {}

        # Sort patterns by priority (lower = higher priority)
        sorted_patterns = sorted(self._patterns, key=lambda p: p.PRIORITY)

        for pattern_class in sorted_patterns:
            pattern = pattern_class(
                self._graph,
                self._variable_manager,
                self._functions,
                self._entry_node,
            )

            # Analyze to get suggested renames
            var_names = pattern.analyze()

            if not var_names:
                continue

            # Apply names, excluding already-renamed variables
            renamed = pattern.apply_names(exclude_vars=self.renamed_variables)

            # Track what was renamed
            for var in renamed:
                if var in var_names:
                    all_renames[var] = var_names[var]
                    self.variable_patterns[var] = pattern_class.__name__

            self.renamed_variables.update(renamed)

            l.debug("Pattern %s renamed %d variables", pattern_class.__name__, len(renamed))

        return all_renames

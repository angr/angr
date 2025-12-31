# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Base class for semantic variable naming patterns.

This module provides two base classes for semantic naming:
- ClinicNamingBase: For passes running in Clinic on AIL graphs
- RegionNamingBase: For passes running in RegionSimplifier on structured regions
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
import logging

from angr.ailment.statement import Call
from angr.ailment.expression import Const
from angr.sim_variable import SimVariable

if TYPE_CHECKING:
    import networkx

    from angr.ailment import Block
    from angr.knowledge_plugins.functions.function_manager import FunctionManager
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
    from angr.analyses.decompiler.structuring.structurer_nodes import BaseNode

l = logging.getLogger(name=__name__)


class SemanticNamingBase(ABC):
    """
    Abstract base class for semantic variable naming patterns.

    Subclasses implement specific naming patterns (loop counters, array indices, etc.)
    This is the common base for both Clinic-based and RegionSimplifier-based passes.
    """

    # Priority determines order of application (lower = higher priority)
    # This matters when the same variable matches multiple patterns
    PRIORITY: int = 100

    def __init__(
        self,
        variable_manager: VariableManagerInternal,
        functions: FunctionManager,
    ):
        self._variable_manager = variable_manager
        self._functions = functions
        self._var_to_new_name: dict[SimVariable, str] = {}

    @abstractmethod
    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze and return a mapping of variables to their suggested names.

        :return: Dictionary mapping SimVariable to suggested name
        """
        raise NotImplementedError

    def apply_names(self, exclude_vars: set[SimVariable] | None = None) -> set[SimVariable]:
        """
        Apply the computed names to the variables.

        :param exclude_vars: Variables to skip (already named by higher priority patterns)
        :return: Set of variables that were renamed
        """
        exclude_vars = exclude_vars or set()
        renamed_vars: set[SimVariable] = set()

        for var, new_name in self._var_to_new_name.items():
            # Skip if already named by another pattern
            if var in exclude_vars:
                continue

            # Check if variable already has a meaningful name (not auto-generated)
            if var.renamed:
                continue

            # Find the unified variable and rename it
            unified_var = self._variable_manager.unified_variable(var)
            target_var = unified_var if unified_var is not None else var

            # Also skip if unified var is in exclude set
            if unified_var in exclude_vars:
                continue

            if unified_var in renamed_vars:
                continue

            l.debug("Renaming %s -> %s (pattern: %s)", target_var.name, new_name, self.__class__.__name__)
            target_var.name = new_name
            target_var.renamed = True
            target_var.clear_hash()
            renamed_vars.add(var)
            if unified_var:
                renamed_vars.add(unified_var)

        return renamed_vars

    # --- Helper methods for subclasses ---

    @staticmethod
    def _get_linked_variable(expr) -> SimVariable | None:
        """
        Get the SimVariable linked to an expression, if any.
        """
        if hasattr(expr, "variable") and expr.variable is not None:
            return expr.variable
        return None

    def _get_function_name(self, call: Call) -> str | None:
        """
        Extract the function name from a Call expression.
        """
        target = call.target

        # Direct function address
        if isinstance(target, Const) and self._functions.contains_addr(target.value_int):
            func = self._functions.get_by_addr(target.value_int)
            return func.name
        if isinstance(target, str):
            return target
        return None

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize a function name for matching."""
        return name.lower().strip("_")


class ClinicNamingBase(SemanticNamingBase):
    """
    Base class for semantic naming passes that run in Clinic on AIL graphs.

    These passes operate on the raw AIL graph before structuring, allowing them
    to analyze control flow patterns directly.
    """

    def __init__(
        self,
        ail_graph: networkx.DiGraph,
        variable_manager: VariableManagerInternal,
        functions: FunctionManager,
        entry_node: Block,
    ):
        super().__init__(variable_manager, functions)
        self._graph = ail_graph
        self._entry_node = entry_node


class RegionNamingBase(SemanticNamingBase):
    """
    Base class for semantic naming passes that run in RegionSimplifier on structured regions.

    These passes operate after structuring, allowing them to leverage structured information
    like LoopNode, ConditionNode, etc. They can reuse loop analysis results from structuring
    instead of re-analyzing the graph.
    """

    def __init__(
        self,
        region: BaseNode,
        variable_manager: VariableManagerInternal,
        functions: FunctionManager,
    ):
        super().__init__(variable_manager, functions)
        self._region = region

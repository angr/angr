# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Base class for semantic variable naming patterns.

This module provides two base classes for semantic naming:
- ClinicNamingBase: For passes running in Clinic on AIL graphs
- RegionNamingBase: For passes running in RegionSimplifier on structured regions
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from angr.ailment.expression import Call, Const
from angr.sim_variable import SimVariable

if TYPE_CHECKING:
    import networkx

    from angr.ailment import Block
    from angr.analyses.decompiler.structurer_nodes import BaseNode
    from angr.analyses.decompiler.variable_map import VariableMap
    from angr.knowledge_plugins.functions.function_manager import FunctionManager
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

l = logging.getLogger(name=__name__)

# The positional names angr gives an argument it has no name for: ``a<i>`` (Function.set_prototype, Clinic), ``arg_<i>``
# (the C++ declaration parser) and ``p<i>`` (Go DWARF signatures). They carry no information, so semantic naming may
# replace them. A Go receiver known only from its type's method table is named ``recv``, which says what the argument
# is, so it is kept.
_PLACEHOLDER_ARG_NAME = re.compile(r"(?:a|arg_|p)\d+")


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
        variable_map: VariableMap,
    ):
        self._variable_manager = variable_manager
        self._functions = functions
        self._variable_map = variable_map
        self._var_to_new_name: dict[SimVariable, str] = {}
        # Original (pre-rename) name of every variable this pattern renames, so the
        # orchestrator can restore it when reverting an over-shared name.
        self.original_names: dict[SimVariable, str | None] = {}

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
        prototype_arg_names = self._prototype_arg_names()
        # the arguments keep these names, so another variable given one would shadow its argument
        argument_names = {name for name in prototype_arg_names if name and not _PLACEHOLDER_ARG_NAME.fullmatch(name)}

        for var, new_name in self._var_to_new_name.items():
            # Skip if already named by another pattern
            if var in exclude_vars:
                continue

            if new_name in argument_names or self._has_meaningful_name(var, prototype_arg_names):
                continue

            # Find the unified variable and rename it
            unified_var = self._variable_manager.unified_variable(var)
            target_var = unified_var if unified_var is not None else var

            # Also skip if unified var is in exclude set
            if unified_var in exclude_vars:
                continue

            if unified_var in renamed_vars:
                continue

            if self._has_meaningful_name(target_var, prototype_arg_names):
                continue

            l.debug("Renaming %s -> %s (pattern: %s)", target_var.name, new_name, self.__class__.__name__)
            self.original_names.setdefault(target_var, target_var.name)
            target_var.name = new_name
            target_var.auto_renamed = True
            target_var.clear_hash()
            renamed_vars.add(var)
            if unified_var:
                renamed_vars.add(unified_var)

        return renamed_vars

    def _prototype_arg_names(self) -> list[str]:
        """
        The argument names of the function's prototype, in argument order; empty when it has no prototype or names.
        """
        func = self._functions.function(addr=self._variable_manager.func_addr)
        proto = func.get_prototype(self._variable_manager.flavor) if func is not None else None
        return list(proto.arg_names) if proto is not None and proto.arg_names else []

    @staticmethod
    def _has_meaningful_name(var: SimVariable, prototype_arg_names: list[str]) -> bool:
        """
        Whether ``var`` already has a name that a pattern must not replace: one the user gave, one an earlier pattern
        gave, or, for a function argument, the name its prototype gives it unless that name is a placeholder.
        """
        if var.renamed or var.auto_renamed:
            return True
        if not var.ident or not var.ident.startswith("arg_"):
            return False
        # Clinic gives the argument whose ident is ``arg_<idx>`` the name ``prototype.arg_names[idx]``
        idx = int(var.ident.removeprefix("arg_"))
        if idx >= len(prototype_arg_names):
            return False
        name = prototype_arg_names[idx]
        return var.name == name and not _PLACEHOLDER_ARG_NAME.fullmatch(name)

    # --- Helper methods for subclasses ---

    def _get_linked_variable(self, expr) -> SimVariable | None:
        """
        Get the SimVariable linked to an expression, if any.
        """
        expr_var = self._variable_map.variable(expr)
        if expr_var is not None:
            return self._variable_manager.unified_variable(expr_var)
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
        variable_map: VariableMap,
    ):
        super().__init__(variable_manager, functions, variable_map)
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
        variable_map,
    ):
        super().__init__(variable_manager, functions, variable_map)
        self._region = region

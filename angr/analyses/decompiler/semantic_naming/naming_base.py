# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Base class for semantic variable naming patterns.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
import logging

from angr.ailment.statement import Call
from angr.ailment.expression import BinaryOp, UnaryOp, Load, Const
from angr.sim_variable import SimVariable

if TYPE_CHECKING:
    import networkx

    from angr.ailment import Block
    from angr.knowledge_plugins.functions.function_manager import FunctionManager
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

l = logging.getLogger(name=__name__)


class SemanticNamingBase(ABC):
    """
    Abstract base class for semantic variable naming patterns.

    Subclasses implement specific naming patterns (loop counters, array indices, etc.)
    """

    # Priority determines order of application (lower = higher priority)
    # This matters when the same variable matches multiple patterns
    PRIORITY: int = 100

    def __init__(
        self,
        ail_graph: networkx.DiGraph,
        variable_manager: VariableManagerInternal,
        functions: FunctionManager,
        entry_node: Block | None = None,
    ):
        self._graph = ail_graph
        self._variable_manager = variable_manager
        self._functions = functions
        self._entry_node = entry_node or self._find_entry_node()
        self._var_to_new_name: dict[SimVariable, str] = {}

    def _find_entry_node(self) -> Block | None:
        """Find the entry node of the graph."""
        if not self._graph:
            return None

        # Find nodes with no predecessors
        entry_candidates = [n for n in self._graph if self._graph.in_degree[n] == 0]
        if entry_candidates:
            return min(entry_candidates, key=lambda n: (n.addr, n.idx or 0))

        # Fall back to node with the lowest address
        return min(self._graph, key=lambda n: (n.addr, n.idx or 0))

    @abstractmethod
    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze the graph and return a mapping of variables to their suggested names.

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
            target_var._hash = None  # Clear hash cache
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

    def _extract_vars_from_expr(self, expr) -> set[SimVariable]:
        """
        Recursively extract all linked variables from an expression.
        """
        vars_found: set[SimVariable] = set()

        if expr is None:
            return vars_found

        # Check if this expression has a linked variable
        var = self._get_linked_variable(expr)
        if var is not None:
            vars_found.add(var)

        # Recursively check operands
        if isinstance(expr, BinaryOp):
            for operand in expr.operands:
                vars_found.update(self._extract_vars_from_expr(operand))
        elif isinstance(expr, UnaryOp):
            vars_found.update(self._extract_vars_from_expr(expr.operand))
        elif isinstance(expr, Load):
            vars_found.update(self._extract_vars_from_expr(expr.addr))

        return vars_found

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

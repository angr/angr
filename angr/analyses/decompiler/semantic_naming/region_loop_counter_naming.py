# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Semantic variable naming for loop counters using structured regions.

This module implements detection and renaming of loop counter variables
using the LoopNode structure from the region simplifier. It operates on
structured regions after the structuring phase, allowing it to reuse
existing loop analysis results instead of re-analyzing the graph.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

from angr.ailment.statement import Statement, Assignment
from angr.ailment.expression import Expression, BinaryOp
from angr.sim_variable import SimVariable
from angr.analyses.decompiler.structuring.structurer_nodes import (
    LoopNode,
    SequenceNode,
    CodeNode,
    ConditionNode,
    CascadingConditionNode,
    BaseNode,
)

from .naming_base import RegionNamingBase

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions.function_manager import FunctionManager
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

l = logging.getLogger(name=__name__)

# Standard loop counter names in order of nesting depth
LOOP_COUNTER_NAMES = ["i", "j", "k", "l", "m", "n"]


class RegionLoopCounterNaming(RegionNamingBase):
    """
    Detects loop counter variables from structured LoopNodes and renames them
    to standard names like i, j, k based on nesting depth.

    This pass operates after structuring and uses the iterator information
    already extracted by LoopSimplifier (stored in LoopNode.iterator).
    """

    PRIORITY = 10  # Highest priority - loop counters are named first

    def __init__(
        self,
        region: BaseNode,
        variable_manager: VariableManagerInternal,
        functions: FunctionManager,
    ):
        super().__init__(region, variable_manager, functions)

        # Track loops and their nesting
        self._loop_nodes: list[LoopNode] = []
        self._loop_info: dict[LoopNode, dict] = {}  # loop_node -> {counter_var, nesting_depth}
        self._name_index = 0

    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze the structured region for loop counters and return a mapping
        of variables to their new names.

        :return: Dictionary mapping SimVariable to new name (e.g., "i", "j", "k")
        """
        if self._region is None:
            return {}

        # Step 1: Collect all LoopNodes from the region
        self._collect_loop_nodes(self._region, nesting_depth=0)

        # Step 2: For each loop, identify the counter variable from iterator
        self._identify_loop_counters()

        # Step 3: Assign names based on nesting depth
        self._assign_counter_names()

        return self._var_to_new_name

    def _collect_loop_nodes(self, node: BaseNode, nesting_depth: int) -> None:
        """
        Recursively collect all LoopNodes from the region structure.

        :param node: The current node to process
        :param nesting_depth: The current loop nesting depth
        """
        if node is None:
            return

        if isinstance(node, LoopNode):
            self._loop_nodes.append(node)
            self._loop_info[node] = {
                "counter_var": None,
                "nesting_depth": nesting_depth,
            }
            self._collect_loop_nodes(node.sequence_node, nesting_depth + 1)

        elif isinstance(node, SequenceNode):
            for child in node.nodes:
                self._collect_loop_nodes(child, nesting_depth)

        elif isinstance(node, CodeNode):
            self._collect_loop_nodes(node.node, nesting_depth)

        elif isinstance(node, ConditionNode):
            if node.true_node is not None:
                self._collect_loop_nodes(node.true_node, nesting_depth)
            if node.false_node is not None:
                self._collect_loop_nodes(node.false_node, nesting_depth)

        elif isinstance(node, CascadingConditionNode):
            for _, child_node in node.condition_and_nodes:
                if isinstance(child_node, BaseNode):
                    self._collect_loop_nodes(child_node, nesting_depth)
            if node.else_node is not None and isinstance(node.else_node, BaseNode):
                self._collect_loop_nodes(node.else_node, nesting_depth)

    def _identify_loop_counters(self) -> None:
        """
        For each loop, identify the counter variable from the iterator.

        The iterator is already extracted by LoopSimplifier and stored in
        LoopNode.iterator. For 'for' loops, this is the increment statement
        (e.g., i += 1).
        """
        for loop_node in self._loop_nodes:
            loop_info = self._loop_info[loop_node]

            # Check if this is a for-loop with an iterator
            if loop_node.sort == "for" and loop_node.iterator is not None:
                # The iterator is typically an Assignment like: i = i + 1
                counter_var = self._extract_counter_from_iterator(loop_node.iterator)
                if counter_var is not None:
                    loop_info["counter_var"] = counter_var
                    continue

            # For while loops or for loops without iterators, try to extract from initializer
            if loop_node.initializer is not None:
                counter_var = self._extract_counter_from_initializer(loop_node.initializer)
                if counter_var is not None:
                    loop_info["counter_var"] = counter_var
                    continue

            # Fall back to extracting from condition
            if loop_node.condition is not None:
                counter_var = self._extract_counter_from_condition(loop_node.condition)
                if counter_var is not None:
                    loop_info["counter_var"] = counter_var

    def _extract_counter_from_iterator(self, iterator) -> SimVariable | None:
        """
        Extract the counter variable from a loop iterator statement.

        Patterns:
        - i = i + 1 (Assignment with Add)
        - i = i - 1 (Assignment with Sub)
        - i++ (equivalent to i = i + 1)
        """
        if not isinstance(iterator, Assignment):
            return None

        dst_var = self._get_linked_variable(iterator.dst)
        if dst_var is None:
            return None

        # The iterator modifies the counter variable
        # We just need to extract the variable from the destination
        return dst_var

    def _extract_counter_from_initializer(self, initializer: Statement) -> SimVariable | None:
        """
        Extract the counter variable from a loop initializer statement.

        Pattern: i = 0 (Assignment with Const)
        """
        if not isinstance(initializer, Assignment):
            return None
        return self._get_linked_variable(initializer.dst)

    def _extract_counter_from_condition(self, condition: Expression) -> SimVariable | None:
        """
        Extract a potential counter variable from the loop condition.

        Patterns:
        - i < n (comparison with variable)
        - i != 0 (comparison with constant)
        """
        if not isinstance(condition, BinaryOp):
            return None

        # Check for comparison operations
        comparison_ops = {"CmpLT", "CmpLE", "CmpGT", "CmpGE", "CmpNE", "CmpEQ"}
        if condition.op not in comparison_ops:
            return None

        # Try to extract variables from the comparison
        op0, op1 = condition.operands

        # Prefer the variable on the left side (common pattern: i < n)
        var0 = self._get_linked_variable(op0)
        if var0 is not None:
            return var0
        return self._get_linked_variable(op1)

    def _assign_counter_names(self) -> None:
        """
        Assign standard names (i, j, k, ...) to counter variables based on nesting depth.
        """
        # Sort loops by nesting depth (outermost first), then by address for stability
        sorted_loops = sorted(
            self._loop_nodes, key=lambda ln: (self._loop_info[ln]["nesting_depth"], ln.addr if ln.addr else 0)
        )

        for loop_node in sorted_loops:
            counter_var = self._loop_info[loop_node]["counter_var"]
            if counter_var is None:
                continue

            # Skip if already named
            if counter_var in self._var_to_new_name:
                continue

            # Check if the unified variable is already named
            unified_var = self._variable_manager.unified_variable(counter_var)
            if unified_var is not None and unified_var in self._var_to_new_name:
                continue

            # Assign next available name
            if self._name_index < len(LOOP_COUNTER_NAMES):
                new_name = LOOP_COUNTER_NAMES[self._name_index]
            else:
                # If we run out of standard names, use i0, i1, etc.
                new_name = f"i{self._name_index - len(LOOP_COUNTER_NAMES)}"

            self._var_to_new_name[counter_var] = new_name
            self._name_index += 1

            l.debug(
                "Identified loop counter %s -> %s at depth %d",
                counter_var.name,
                new_name,
                self._loop_info[loop_node]["nesting_depth"],
            )

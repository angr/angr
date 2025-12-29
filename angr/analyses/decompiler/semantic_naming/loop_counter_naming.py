# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Semantic variable naming for loop counters.

This module implements detection and renaming of loop counter variables
(e.g., renaming them to i, j, k based on loop nesting).
"""
from __future__ import annotations
import logging
from collections import defaultdict

from angr import ailment
from angr.ailment.expression import BinaryOp, Const
from angr.ailment.statement import Assignment, ConditionalJump
from angr.sim_variable import SimVariable
from angr.utils.graph import dfs_back_edges

from .naming_base import SemanticNamingBase

l = logging.getLogger(name=__name__)

# Standard loop counter names in order of nesting depth
LOOP_COUNTER_NAMES = ["i", "j", "k", "l", "m", "n"]


class LoopCounterNaming(SemanticNamingBase):
    """
    Detects loop counter variables in an AIL graph and renames them
    to standard names like i, j, k based on nesting depth.
    """

    PRIORITY = 10  # Highest priority - loop counters are named first

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Track loops and their nesting
        self._loop_heads: list[ailment.Block] = []
        self._loop_info: dict[ailment.Block, dict] = {}  # loop_head -> {nodes, counter_var, nesting_depth}

    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze the graph for loop counters and return a mapping
        of variables to their new names.

        :return: Dictionary mapping SimVariable to new name (e.g., "i", "j", "k")
        """
        if not self._entry_node or not self._graph:
            return {}

        # Step 1: Find all loops using back edges
        self._find_loops()

        # Step 2: Compute loop nesting depths
        self._compute_nesting_depths()

        # Step 3: For each loop, identify the counter variable
        self._identify_loop_counters()

        # Step 4: Assign names based on nesting depth
        self._assign_counter_names()

        return self._var_to_new_name

    def _find_loops(self) -> None:
        """
        Find all natural loops in the graph using back edges.
        """
        try:
            back_edges = list(dfs_back_edges(self._graph, self._entry_node))
        except Exception:  # pylint:disable=broad-except
            l.debug("Failed to find back edges in graph")
            return

        # Group back edges by their target (loop head)
        head_to_latches: dict[ailment.Block, set[ailment.Block]] = defaultdict(set)
        for latch, head in back_edges:
            head_to_latches[head].add(latch)

        # For each loop head, find the loop body
        for head, latches in head_to_latches.items():
            loop_nodes = self._find_loop_body(head, latches)
            self._loop_heads.append(head)
            self._loop_info[head] = {
                "nodes": loop_nodes,
                "latches": latches,
                "counter_var": None,
                "nesting_depth": 0,
            }

    def _find_loop_body(self, head: ailment.Block, latches: set[ailment.Block]) -> set[ailment.Block]:
        """
        Find all nodes in a natural loop given the head and latching nodes.
        Uses reverse reachability from latches to head.
        """
        loop_nodes = {head}

        # Work backwards from each latch to find all nodes in the loop
        worklist = list(latches)
        while worklist:
            node = worklist.pop()
            if node not in loop_nodes:
                loop_nodes.add(node)
                # Add predecessors that aren't the head
                for pred in self._graph.predecessors(node):
                    if pred not in loop_nodes:
                        worklist.append(pred)

        return loop_nodes

    def _compute_nesting_depths(self) -> None:
        """Compute the nesting depth for each loop."""
        # Sort loops by size (smaller loops are likely inner loops)
        sorted_heads = sorted(self._loop_heads, key=lambda h: len(self._loop_info[h]["nodes"]))

        for head in sorted_heads:
            depth = 0

            # Check how many other loops contain this loop's head
            for other_head in self._loop_heads:
                if other_head == head:
                    continue
                other_nodes = self._loop_info[other_head]["nodes"]
                if head in other_nodes:
                    depth += 1

            self._loop_info[head]["nesting_depth"] = depth

    def _identify_loop_counters(self) -> None:
        """
        For each loop, identify the counter variable.
        A loop counter is typically:
        1. Modified (incremented/decremented) in the loop body
        2. Used in the loop condition (comparison)
        """
        for head in self._loop_heads:
            loop_info = self._loop_info[head]
            loop_nodes = loop_info["nodes"]

            # Find variables that are:
            # 1. Modified with increment/decrement patterns in the loop
            # 2. Used in comparisons (likely in the condition)

            modified_vars = self._find_modified_vars_with_increment(loop_nodes)
            condition_vars = self._find_condition_vars(head, loop_nodes)

            # The counter is likely a variable that's both modified with increment
            # and used in the condition
            counter_candidates = modified_vars & condition_vars

            if counter_candidates:
                # Prefer the variable that appears in the head block's condition
                counter = self._pick_best_counter(counter_candidates, head)
                loop_info["counter_var"] = counter
            elif modified_vars:
                # Fall back to any variable with increment pattern
                loop_info["counter_var"] = next(iter(modified_vars))

    def _find_modified_vars_with_increment(self, loop_nodes: set[ailment.Block]) -> set[SimVariable]:
        """
        Find variables that are modified with increment/decrement patterns.
        Patterns: v = v + 1, v = v - 1, v++, v--, etc.
        """
        increment_vars: set[SimVariable] = set()

        for node in loop_nodes:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                if not isinstance(stmt, Assignment):
                    continue

                dst = stmt.dst
                src = stmt.src

                # Get the variable being assigned to
                dst_var = self._get_linked_variable(dst)
                if dst_var is None:
                    continue

                # Check if it's an increment/decrement pattern: v = v +/- const
                if isinstance(src, BinaryOp) and src.op in ("Add", "Sub"):
                    op0, op1 = src.operands
                    op0_var = self._get_linked_variable(op0)
                    op1_var = self._get_linked_variable(op1)

                    # Check patterns: v = v + const or v = const + v
                    if (op0_var == dst_var and isinstance(op1, Const)) or (
                        op1_var == dst_var and isinstance(op0, Const)
                    ):
                        increment_vars.add(dst_var)

        return increment_vars

    def _find_condition_vars(self, head: ailment.Block, loop_nodes: set[ailment.Block]) -> set[SimVariable]:
        """
        Find variables used in loop conditions.
        Check the conditional jump in the head block or any block that exits the loop.
        """
        condition_vars: set[SimVariable] = set()

        # Check all blocks for conditional jumps that might be loop conditions
        for node in loop_nodes:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                if isinstance(stmt, ConditionalJump):
                    vars_in_condition = self._extract_vars_from_expr(stmt.condition)
                    condition_vars.update(vars_in_condition)

        return condition_vars

    def _pick_best_counter(self, candidates: set[SimVariable], head: ailment.Block) -> SimVariable:
        """
        Pick the best counter variable from candidates.
        Prefer variables used in the head block's condition.
        """
        # Find variables in head's conditional jump
        head_condition_vars: set[SimVariable] = set()
        for stmt in head.statements:
            if isinstance(stmt, ConditionalJump):
                head_condition_vars = self._extract_vars_from_expr(stmt.condition)
                break

        # Prefer variables in head's condition
        intersection = candidates & head_condition_vars
        if intersection:
            return next(iter(intersection))

        return next(iter(candidates))

    def _assign_counter_names(self) -> None:
        """
        Assign standard names (i, j, k, ...) to counter variables based on nesting depth.
        """

        # Sort loops by nesting depth (outermost first)
        sorted_loops = sorted(self._loop_heads, key=lambda h: (self._loop_info[h]["nesting_depth"], h.addr))

        # Track which names have been used
        name_index = 0

        for head in sorted_loops:
            counter_var = self._loop_info[head]["counter_var"]
            if counter_var is None:
                continue

            # Skip if already named
            if counter_var in self._var_to_new_name:
                continue

            # Assign next available name
            if name_index < len(LOOP_COUNTER_NAMES):
                new_name = LOOP_COUNTER_NAMES[name_index]
                self._var_to_new_name[counter_var] = new_name
                name_index += 1
            else:
                # If we run out of standard names, use i0, i1, etc.
                new_name = f"i{name_index - len(LOOP_COUNTER_NAMES)}"
                self._var_to_new_name[counter_var] = new_name
                name_index += 1

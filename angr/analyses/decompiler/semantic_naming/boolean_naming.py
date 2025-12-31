# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Semantic variable naming for boolean flag variables.

This module detects variables used as boolean flags and names them appropriately
(e.g., found, done, flag, ok).
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import logging
from collections import defaultdict

from angr import ailment
from angr.ailment.expression import BinaryOp, UnaryOp, Const
from angr.ailment.statement import Assignment, ConditionalJump
from angr.sim_variable import SimVariable

from .naming_base import ClinicNamingBase

if TYPE_CHECKING:
    pass

l = logging.getLogger(name=__name__)

# Names for boolean flag variables
BOOLEAN_FLAG_NAMES = ["result"]


class BooleanNaming(ClinicNamingBase):
    """
    Detects variables used as boolean flags and renames them.

    Boolean flag patterns detected:
    - Variables assigned only 0 or 1
    - Variables used directly in conditions (if (var) or if (!var))
    - Variables compared to 0 or 1
    - Variables that are results of comparison operations
    """

    PRIORITY = 80  # Lower priority than other patterns

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._bool_candidates: dict[SimVariable, dict] = {}  # var -> {score, assignments, conditions}
        self._name_counter = 0

    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze the graph for boolean flag patterns.

        :return: Dictionary mapping SimVariable to new name
        """
        if not self._graph:
            return {}

        # Find variables with boolean-like usage patterns
        self._find_boolean_assignments()
        self._find_boolean_conditions()
        self._find_comparison_results()

        # Score and filter candidates
        self._score_candidates()

        # Assign names to high-confidence boolean variables
        self._assign_boolean_names()

        return self._var_to_new_name

    def _find_boolean_assignments(self) -> None:
        """Find variables that are only assigned 0 or 1."""
        var_assignments: dict[SimVariable, list[int | None]] = defaultdict(list)

        for node in self._graph:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                if not isinstance(stmt, Assignment):
                    continue

                dst_var = self._get_linked_variable(stmt.dst)
                if dst_var is None:
                    continue

                # Check if assigned a constant 0 or 1
                if isinstance(stmt.src, Const):
                    val = stmt.src.value
                    if val in (0, 1):
                        var_assignments[dst_var].append(val)
                    else:
                        # Assigned a non-boolean constant
                        var_assignments[dst_var].append(None)

                # Check if assigned a comparison result
                elif isinstance(stmt.src, BinaryOp) and self._is_comparison_op(stmt.src.op):
                    var_assignments[dst_var].append(1)  # Comparison results are boolean

                # Check if assigned a logical operation result
                elif isinstance(stmt.src, BinaryOp) and stmt.src.op in ("LogicalAnd", "LogicalOr"):
                    var_assignments[dst_var].append(1)  # Logical ops are boolean

                # Check for negation of another variable
                elif isinstance(stmt.src, UnaryOp) and stmt.src.op == "Not":
                    var_assignments[dst_var].append(1)  # Negation suggests boolean

                else:
                    # Other assignment - might not be boolean
                    var_assignments[dst_var].append(None)

        # Record candidates that are only assigned boolean-like values
        for var, assignments in var_assignments.items():
            if not assignments:
                continue

            # Count how many assignments are boolean-like
            bool_count = sum(1 for a in assignments if a is not None)
            total_count = len(assignments)

            if bool_count > 0:
                self._init_candidate(var)
                # Higher score if all assignments are boolean
                if bool_count == total_count:
                    self._bool_candidates[var]["score"] += 30
                else:
                    self._bool_candidates[var]["score"] += 10 * (bool_count / total_count)
                self._bool_candidates[var]["bool_assignments"] = bool_count

    def _find_boolean_conditions(self) -> None:
        """Find variables used directly in conditions."""
        for node in self._graph:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                if not isinstance(stmt, ConditionalJump):
                    continue

                cond = stmt.condition

                # Check for direct variable use: if (var)
                var = self._get_linked_variable(cond)
                if var is not None:
                    self._init_candidate(var)
                    self._bool_candidates[var]["score"] += 25
                    self._bool_candidates[var]["direct_condition"] = True
                    continue

                # Check for negation: if (!var)
                if isinstance(cond, UnaryOp) and cond.op == "Not":
                    var = self._get_linked_variable(cond.operand)
                    if var is not None:
                        self._init_candidate(var)
                        self._bool_candidates[var]["score"] += 25
                        self._bool_candidates[var]["direct_condition"] = True
                        continue

                # Check for comparison to 0 or 1: if (var == 0) or if (var != 0)
                if isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE"):
                    op0, op1 = cond.operands
                    var = None

                    if isinstance(op1, Const) and op1.value in (0, 1):
                        var = self._get_linked_variable(op0)
                    elif isinstance(op0, Const) and op0.value in (0, 1):
                        var = self._get_linked_variable(op1)

                    if var is not None:
                        self._init_candidate(var)
                        self._bool_candidates[var]["score"] += 20
                        self._bool_candidates[var]["compared_to_bool"] = True

    def _find_comparison_results(self) -> None:
        """Find variables that store comparison results."""
        for node in self._graph:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                if not isinstance(stmt, Assignment):
                    continue

                dst_var = self._get_linked_variable(stmt.dst)
                if dst_var is None:
                    continue

                # Check if the source is a comparison
                if isinstance(stmt.src, BinaryOp) and self._is_comparison_op(stmt.src.op):
                    self._init_candidate(dst_var)
                    self._bool_candidates[dst_var]["score"] += 20
                    self._bool_candidates[dst_var]["comparison_result"] = True

    @staticmethod
    def _is_comparison_op(op: str) -> bool:
        """Check if an operation is a comparison."""
        comparison_ops = {"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"}
        return op in comparison_ops

    def _init_candidate(self, var: SimVariable) -> None:
        """Initialize a candidate entry if not exists."""
        if var not in self._bool_candidates:
            self._bool_candidates[var] = {
                "score": 0,
                "bool_assignments": 0,
                "direct_condition": False,
                "compared_to_bool": False,
                "comparison_result": False,
            }

    def _score_candidates(self) -> None:
        """Apply additional scoring heuristics."""
        for var, info in self._bool_candidates.items():
            # Bonus for small variables (likely to be flags)
            if hasattr(var, "size") and var.size is not None and var.size <= 4:  # 4 bytes or less
                info["score"] += 5

            # Bonus for having multiple boolean indicators
            indicators = sum(
                [
                    info["direct_condition"],
                    info["compared_to_bool"],
                    info["comparison_result"],
                    info["bool_assignments"] > 0,
                ]
            )
            if indicators >= 2:
                info["score"] += 15

    def _assign_boolean_names(self) -> None:
        """Assign names to high-confidence boolean variables."""
        # Sort by score (highest first)
        sorted_candidates = sorted(self._bool_candidates.items(), key=lambda x: -x[1]["score"])

        # Threshold for considering a variable as boolean
        SCORE_THRESHOLD = 25

        for var, info in sorted_candidates:
            if info["score"] < SCORE_THRESHOLD:
                continue

            # Skip if already has a meaningful name
            if var.name and not var.name.startswith("v") and not var.name.startswith("var_"):
                continue

            # Check unified variable too
            unified = self._variable_manager.unified_variable(var)
            if unified and unified.name and not unified.name.startswith("v"):
                continue

            # Assign a name
            if self._name_counter < len(BOOLEAN_FLAG_NAMES):
                new_name = BOOLEAN_FLAG_NAMES[self._name_counter]
            else:
                new_name = f"flag{self._name_counter}"

            self._var_to_new_name[var] = new_name
            self._name_counter += 1

            l.debug(
                "Identified boolean flag %s (score=%d, direct_cond=%s, cmp_result=%s)",
                var.name,
                info["score"],
                info["direct_condition"],
                info["comparison_result"],
            )

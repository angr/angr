# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Semantic variable naming for array indices.

This module detects variables used as array indices and names them appropriately.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Const, Load
from angr.ailment.statement import Store
from angr.sim_variable import SimVariable

from .naming_base import ClinicNamingBase

if TYPE_CHECKING:
    from angr.ailment import Expression


l = logging.getLogger(name=__name__)

# Names for array indices (used when not already named as loop counter)
ARRAY_INDEX_NAMES = ["idx", "index", "pos", "off"]


class ArrayIndexNaming(ClinicNamingBase):
    """
    Detects variables used as array indices and renames them.

    Array index patterns detected:
    - base + idx * scale (common array indexing)
    - base + idx (byte array or pointer arithmetic)
    - ptr[idx] style access
    """

    PRIORITY = 50  # Lower priority than loop counters

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._index_vars: dict[SimVariable, int] = {}  # var -> usage count
        self._name_counter = 0

    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze the graph for array index patterns.

        :return: Dictionary mapping SimVariable to new name
        """
        if not self._graph:
            return {}

        # Find all variables used as array indices
        self._find_array_indices()

        # Assign names based on usage frequency
        self._assign_index_names()

        return self._var_to_new_name

    def _find_array_indices(self) -> None:
        """
        Find variables used in array indexing patterns.
        """
        for node in self._graph:
            if not isinstance(node, Block):
                continue

            for stmt in node.statements:
                # Check Load expressions
                self._check_expr_for_indices(stmt)

    def _check_expr_for_indices(self, node) -> None:
        """
        Recursively check an expression/statement for array index patterns.
        """
        if node is None:
            return

        # Check if this is a Load with array-style addressing
        if isinstance(node, Load):
            self._analyze_address_expr(node.addr)
            # Also check nested expressions
            self._check_expr_for_indices(node.addr)
            return

        # Check Store statements
        if isinstance(node, Store):
            self._analyze_address_expr(node.addr)
            self._check_expr_for_indices(node.addr)
            self._check_expr_for_indices(node.data)
            return

        # Recursively check BinaryOp operands
        if isinstance(node, BinaryOp):
            for operand in node.operands:
                self._check_expr_for_indices(operand)
            return

        # Check statement attributes
        if hasattr(node, "src"):
            self._check_expr_for_indices(node.src)
        if hasattr(node, "dst"):
            self._check_expr_for_indices(node.dst)

    def _analyze_address_expr(self, addr_expr: Expression) -> None:
        """
        Analyze an address expression for array indexing patterns.

        Patterns:
        - base + idx * scale  (e.g., arr + i * 4)
        - base + idx          (e.g., arr + i for byte arrays)
        - (base + idx * scale) for nested expressions
        """
        if not isinstance(addr_expr, BinaryOp):
            return

        if addr_expr.op != "Add":
            return

        op0, op1 = addr_expr.operands

        # Pattern: base + idx * scale
        if isinstance(op1, BinaryOp) and op1.op == "Mul":
            self._check_mul_for_index(op1)
        elif isinstance(op0, BinaryOp) and op0.op == "Mul":
            self._check_mul_for_index(op0)

        # Pattern: base + idx (could be byte array or already scaled)
        # Only consider if one operand looks like a base (constant or large value)
        # and the other is a variable
        else:
            self._check_add_for_index(op0, op1)

    def _check_mul_for_index(self, mul_expr: BinaryOp) -> None:
        """
        Check a multiplication expression for array index pattern (idx * scale).
        """
        op0, op1 = mul_expr.operands

        # One operand should be a constant (the scale factor)
        # The other should be a variable (the index)
        if isinstance(op1, Const):
            # op0 is potentially the index
            var = self._get_linked_variable(op0)
            if var is not None:
                self._record_index_var(var)
        elif isinstance(op0, Const):
            # op1 is potentially the index
            var = self._get_linked_variable(op1)
            if var is not None:
                self._record_index_var(var)

    def _check_add_for_index(self, op0, op1) -> None:
        """
        Check an addition for simple array index pattern (base + idx).
        """

        # Heuristic: if one operand is a constant (base address) and the other is a variable, the variable might be an
        # index
        var0 = self._get_linked_variable(op0)
        var1 = self._get_linked_variable(op1)

        if isinstance(op0, Const) and var1 is not None:
            # op1 is the potential index
            self._record_index_var(var1)
        elif isinstance(op1, Const) and var0 is not None:
            # op0 is the potential index
            self._record_index_var(var0)

    def _record_index_var(self, var: SimVariable) -> None:
        """
        Record a variable as being used as an array index.
        """
        if var not in self._index_vars:
            self._index_vars[var] = 0
        self._index_vars[var] += 1

    def _assign_index_names(self) -> None:
        """
        Assign names to array index variables.
        """

        # Sort by usage count (most used first)
        sorted_vars = sorted(self._index_vars.items(), key=lambda x: -x[1])

        for var, _count in sorted_vars:
            # Assign a name
            if self._name_counter < len(ARRAY_INDEX_NAMES):
                new_name = ARRAY_INDEX_NAMES[self._name_counter]
            else:
                new_name = f"idx{self._name_counter}"

            self._var_to_new_name[var] = new_name
            self._name_counter += 1

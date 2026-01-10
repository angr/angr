# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Semantic variable naming for pointer variables.

This module detects variables used as pointers and names them appropriately
(e.g., ptr, p, cur, next, prev).
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import logging
from collections import defaultdict

from angr import ailment
from angr.ailment.expression import BinaryOp, UnaryOp, Const, Load
from angr.ailment.statement import Assignment, Store, Call
from angr.sim_variable import SimVariable

from .naming_base import ClinicNamingBase

if TYPE_CHECKING:
    from angr.ailment import Expression

l = logging.getLogger(name=__name__)

# Names for pointer variables based on usage pattern
POINTER_NAMES = {
    "generic": ["ptr", "p", "addr"],
    "iterator": ["cur", "iter", "node"],
    "linked_list": ["next", "prev", "head", "tail"],
    "string": ["str", "s", "buf"],
    "array": ["arr", "data", "base"],
}

# Functions that return pointers
POINTER_RETURNING_FUNCTIONS = {
    "malloc",
    "calloc",
    "realloc",
    "alloca",
    "strdup",
    "strndup",
    "strchr",
    "strrchr",
    "strstr",
    "strpbrk",
    "memchr",
    "memmem",
    "fopen",
    "fdopen",
    "tmpfile",
    "opendir",
    "dlopen",
    "dlsym",
    "mmap",
    "fgets",
    "gets",
}

# Functions that take pointer parameters (param_index -> is_output)
POINTER_PARAM_FUNCTIONS = {
    "memcpy": {0: True, 1: False},  # dst, src
    "memmove": {0: True, 1: False},
    "memset": {0: True},
    "strcpy": {0: True, 1: False},
    "strncpy": {0: True, 1: False},
    "strcat": {0: True, 1: False},
    "strcmp": {0: False, 1: False},
    "strncmp": {0: False, 1: False},
    "strlen": {0: False},
    "free": {0: False},
    "fread": {0: True},
    "fwrite": {0: False},
    "fprintf": {0: False},
    "sprintf": {0: True},
    "snprintf": {0: True},
}


class PointerNaming(ClinicNamingBase):
    """
    Detects variables used as pointers and renames them.

    Pointer patterns detected:
    - Variables used as addresses in Load/Store operations
    - Variables involved in pointer arithmetic
    - Variables passed to functions expecting pointers
    - Variables receiving pointer-returning function results
    - Variables used in linked-list patterns (next/prev access)
    """

    PRIORITY = 45  # After loop counters, before array indices

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pointer_candidates: dict[SimVariable, dict] = {}
        self._name_counter = defaultdict(int)  # category -> count

    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze the graph for pointer variable patterns.

        :return: Dictionary mapping SimVariable to new name
        """
        if not self._graph:
            return {}

        # Find variables used as pointers in various patterns
        self._find_dereference_pointers()
        self._find_pointer_arithmetic()
        self._find_function_pointer_params()
        self._find_linked_list_patterns()

        # Score and assign names
        self._assign_pointer_names()

        return self._var_to_new_name

    def _find_dereference_pointers(self) -> None:
        """Find variables used as addresses in Load/Store operations."""
        for node in self._graph:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                # Check Store statements
                if isinstance(stmt, Store):
                    self._check_address_expr(stmt.addr, "store")

                # Check assignments with Load on the right side
                if isinstance(stmt, Assignment):
                    self._check_expr_for_loads(stmt.src)
                    # Also check if dst is a dereference
                    if isinstance(stmt.dst, Load):
                        self._check_address_expr(stmt.dst.addr, "store")

    def _check_expr_for_loads(self, expr) -> None:
        """Recursively check expression for Load operations."""
        if expr is None:
            return

        if isinstance(expr, Load):
            self._check_address_expr(expr.addr, "load")
            return

        if isinstance(expr, BinaryOp):
            for operand in expr.operands:
                self._check_expr_for_loads(operand)
        elif isinstance(expr, UnaryOp):
            self._check_expr_for_loads(expr.operand)

    def _check_address_expr(self, addr_expr: Expression, access_type: str) -> None:
        """Check an address expression for pointer variables."""
        # Direct variable as address
        var = self._get_linked_variable(addr_expr)
        if var is not None:
            self._record_pointer(var, "dereference", access_type)
            return

        # Pointer arithmetic: ptr + offset or ptr - offset
        if isinstance(addr_expr, BinaryOp) and addr_expr.op in ("Add", "Sub"):
            op0, op1 = addr_expr.operands

            # Check if one operand is a variable (the pointer)
            var0 = self._get_linked_variable(op0)
            var1 = self._get_linked_variable(op1)

            if var0 is not None and (isinstance(op1, Const) or self._is_index_like(op1)):
                self._record_pointer(var0, "arithmetic", access_type)
            elif var1 is not None and isinstance(op0, Const):
                self._record_pointer(var1, "arithmetic", access_type)

    @staticmethod
    def _is_index_like(expr: Expression) -> bool:
        """
        Check if expression looks like an index (e.g., i * 4).
        """
        if isinstance(expr, BinaryOp) and expr.op == "Mul":
            op0, op1 = expr.operands
            return isinstance(op0, Const) or isinstance(op1, Const)
        return False

    def _find_pointer_arithmetic(self) -> None:
        """
        Find variables involved in pointer arithmetic patterns.
        """
        for node in self._graph:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                if not isinstance(stmt, Assignment):
                    continue

                dst_var = self._get_linked_variable(stmt.dst)
                if dst_var is None:
                    continue

                src = stmt.src

                # Pattern: ptr = ptr + offset (pointer increment)
                if isinstance(src, BinaryOp) and src.op in ("Add", "Sub"):
                    op0, _ = src.operands
                    src_var = self._get_linked_variable(op0)

                    if src_var == dst_var:
                        # Self-increment: ptr = ptr + something
                        self._record_pointer(dst_var, "increment", "write")

                # Pattern: ptr = other_ptr (pointer copy/assignment)
                src_var = self._get_linked_variable(src)
                if src_var is not None and src_var in self._pointer_candidates:
                    # Copying from a known pointer
                    self._record_pointer(dst_var, "copy", "write")

    def _find_function_pointer_params(self) -> None:
        """Find variables passed as pointer parameters to functions."""
        for node in self._graph:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                if isinstance(stmt, Call):
                    self._analyze_call_for_pointers(stmt)
                elif isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                    self._analyze_call_for_pointers(stmt.src)

    def _analyze_call_for_pointers(self, call: Call) -> None:
        """Analyze a function call for pointer parameters and return values."""
        func_name = self._get_function_name(call)

        # Check return value
        if call.ret_expr is not None:
            ret_var = self._get_linked_variable(call.ret_expr)
            if ret_var is not None and func_name and self._normalize_name(func_name) in POINTER_RETURNING_FUNCTIONS:
                self._record_pointer(ret_var, "return_value", "write")

        # Check parameters
        if call.args is None:
            return

        if func_name:
            normalized = self._normalize_name(func_name)
            if normalized in POINTER_PARAM_FUNCTIONS:
                param_info = POINTER_PARAM_FUNCTIONS[normalized]
                for idx, is_output in param_info.items():
                    if idx < len(call.args):
                        var = self._get_linked_variable(call.args[idx])
                        if var is not None:
                            access = "write" if is_output else "read"
                            self._record_pointer(var, "func_param", access)

    def _find_linked_list_patterns(self) -> None:
        """Find variables used in linked-list traversal patterns."""
        for node in self._graph:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                if not isinstance(stmt, Assignment):
                    continue

                dst_var = self._get_linked_variable(stmt.dst)
                if dst_var is None:
                    continue

                # Pattern: cur = cur->next (or similar field access)
                # This shows up as: cur = *(cur + offset)
                if isinstance(stmt.src, Load):
                    addr = stmt.src.addr
                    if isinstance(addr, BinaryOp) and addr.op == "Add":
                        op0, op1 = addr.operands
                        src_var = self._get_linked_variable(op0)

                        if src_var == dst_var and isinstance(op1, Const):
                            # Self-referential: cur = *(cur + offset)
                            # This is a classic linked-list traversal pattern
                            self._record_pointer(dst_var, "linked_list", "iterator")

    def _record_pointer(self, var: SimVariable, pattern: str, access: str) -> None:
        """Record a variable as being used as a pointer."""
        if var not in self._pointer_candidates:
            self._pointer_candidates[var] = {
                "score": 0,
                "patterns": set(),
                "accesses": set(),
                "is_iterator": False,
                "is_linked_list": False,
            }

        info = self._pointer_candidates[var]
        info["patterns"].add(pattern)
        info["accesses"].add(access)

        # Score based on pattern
        pattern_scores = {
            "dereference": 25,
            "arithmetic": 20,
            "increment": 15,
            "func_param": 15,
            "return_value": 20,
            "copy": 10,
            "linked_list": 30,
        }
        info["score"] += pattern_scores.get(pattern, 10)

        # Mark special types
        if pattern == "linked_list":
            info["is_linked_list"] = True
        if pattern == "increment" or access == "iterator":
            info["is_iterator"] = True

    def _assign_pointer_names(self) -> None:
        """Assign names to pointer variables."""
        # Sort by score (highest first)
        sorted_candidates = sorted(self._pointer_candidates.items(), key=lambda x: -x[1]["score"])

        # Threshold for considering a variable as a pointer
        SCORE_THRESHOLD = 20

        for var, info in sorted_candidates:
            if info["score"] < SCORE_THRESHOLD:
                continue

            # Choose name based on usage pattern
            category = "iterator" if info["is_linked_list"] or info["is_iterator"] else "generic"

            names = POINTER_NAMES[category]
            idx = self._name_counter[category]

            new_name = names[idx] if idx < len(names) else f"ptr{sum(self._name_counter.values())}"
            self._var_to_new_name[var] = new_name
            self._name_counter[category] += 1

            l.debug("Identified pointer %s (score=%d, patterns=%s)", var.name, info["score"], info["patterns"])

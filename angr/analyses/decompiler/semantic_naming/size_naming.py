# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Semantic variable naming for size/length/count variables.

This module detects variables used as sizes, lengths, or counts and names them
appropriately (e.g., size, len, count, n).
"""
from __future__ import annotations
import logging
from collections import defaultdict

from angr.ailment import Block
from angr.ailment.statement import Call
from angr.sim_variable import SimVariable

from .naming_base import ClinicNamingBase

l = logging.getLogger(name=__name__)


# Functions that take size/length parameters (param_index: name)
SIZE_PARAM_FUNCTIONS = {
    # Memory functions (param positions are 0-indexed)
    "malloc": {0: "size"},
    "calloc": {0: "count", 1: "size"},
    "realloc": {1: "size"},
    "memcpy": {2: "n"},
    "memmove": {2: "n"},
    "memset": {2: "n"},
    "memcmp": {2: "n"},
    # String functions
    "strncpy": {2: "n"},
    "strncat": {2: "n"},
    "strncmp": {2: "n"},
    "strnlen": {1: "n"},
    # I/O functions
    "read": {2: "count"},
    "write": {2: "count"},
    "fread": {1: "size", 2: "count"},
    "fwrite": {1: "size", 2: "count"},
    "recv": {2: "len"},
    "send": {2: "len"},
    "recvfrom": {2: "len"},
    "sendto": {2: "len"},
    # Buffer operations
    "snprintf": {1: "size"},
    "vsnprintf": {1: "size"},
    "fgets": {1: "size"},
}


class SizeNaming(ClinicNamingBase):
    """
    Detects variables used as sizes, lengths, or counts based on:
    1. Being passed as size parameters to known functions
    2. Being used in loop bounds (compared with loop counters)
    3. Having names that suggest size semantics
    """

    PRIORITY = 70  # After call results

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._size_vars: dict[SimVariable, str] = {}  # var -> suggested name
        self._var_usage_count: dict[SimVariable, int] = defaultdict(int)

    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze the graph for size/length variable patterns.

        :return: Dictionary mapping SimVariable to new name
        """
        if not self._graph:
            return {}

        # Find variables passed as size parameters to known functions
        self._find_size_params()

        # Convert to var_to_new_name
        self._var_to_new_name = dict(self._size_vars)

        return self._var_to_new_name

    def _find_size_params(self) -> None:
        """
        Find variables passed as size parameters to known functions.
        """
        for node in self._graph:
            if not isinstance(node, Block):
                continue

            for stmt in node.statements:
                if isinstance(stmt, Call):
                    self._analyze_call_params(stmt)

    def _analyze_call_params(self, call: Call) -> None:
        """
        Analyze a function call for size parameters.
        """
        func_name = self._get_function_name(call)
        if func_name is None:
            return
        normalized = self._normalize_name(func_name)

        # Check if we have size parameter info for this function
        if normalized not in SIZE_PARAM_FUNCTIONS:
            # Check for partial matches
            for pattern in SIZE_PARAM_FUNCTIONS:
                if pattern in normalized:
                    normalized = pattern
                    break
            else:
                return

        param_info = SIZE_PARAM_FUNCTIONS[normalized]

        # Check each argument
        if call.args is None:
            return

        for param_idx, suggested_name in param_info.items():
            if param_idx < len(call.args):
                arg = call.args[param_idx]
                var = self._get_linked_variable(arg)
                if var is not None:
                    self._record_size_var(var, suggested_name)

    def _record_size_var(self, var: SimVariable, suggested_name: str) -> None:
        """
        Record a variable as a size/length variable.
        """
        if var not in self._size_vars:
            self._size_vars[var] = suggested_name
            self._var_usage_count[var] += 1
        else:
            # If already recorded, increment usage count
            self._var_usage_count[var] += 1

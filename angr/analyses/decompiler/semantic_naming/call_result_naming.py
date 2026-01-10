# pylint:disable=missing-class-docstring,missing-function-docstring
"""
Semantic variable naming for function call results.

This module detects variables that store function call results and names them
based on the called function (e.g., malloc result -> ptr, strlen result -> len).
"""
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

from angr import ailment
from angr.ailment.statement import Assignment, Call
from angr.sim_variable import SimVariable

from .naming_base import ClinicNamingBase

if TYPE_CHECKING:
    pass

l = logging.getLogger(name=__name__)

# Mapping of function names/patterns to suggested variable names
FUNCTION_RESULT_NAMES = {
    # Memory allocation
    "malloc": "ptr",
    "calloc": "ptr",
    "realloc": "ptr",
    "alloca": "ptr",
    "mmap": "ptr",
    "new": "ptr",
    # String functions
    "strlen": "len",
    "wcslen": "len",
    "strnlen": "len",
    "strcpy": "dst",
    "strncpy": "dst",
    "strcat": "dst",
    "strncat": "dst",
    "strchr": "ptr",
    "strrchr": "ptr",
    "strstr": "ptr",
    "strdup": "str",
    "strtok": "tok",
    # Memory functions
    "memcpy": "dst",
    "memmove": "dst",
    "memset": "dst",
    "memchr": "ptr",
    # File I/O
    "fopen": "fp",
    "fdopen": "fp",
    "freopen": "fp",
    "tmpfile": "fp",
    "fread": "count",
    "fwrite": "count",
    "fgets": "str",
    "fgetc": "ch",
    "getc": "ch",
    "getchar": "ch",
    # Process/system
    "fork": "pid",
    "getpid": "pid",
    "getppid": "pid",
    "getuid": "uid",
    "geteuid": "uid",
    "getgid": "gid",
    "getegid": "gid",
    # Network
    "socket": "sock",
    "accept": "sock",
    "recv": "count",
    "recvfrom": "count",
    "send": "count",
    "sendto": "count",
    "read": "count",
    "write": "count",
    # Error handling
    "errno": "err",
    "strerror": "msg",
    "perror": "msg",
    # Conversion
    "atoi": "num",
    "atol": "num",
    "atoll": "num",
    "strtol": "num",
    "strtoul": "num",
    "strtoll": "num",
    "strtod": "num",
    # Time
    "time": "t",
    "clock": "t",
    "localtime": "tm",
    "gmtime": "tm",
    # Other common functions
    "sizeof": "size",
    "count": "count",
    "size": "size",
    "length": "len",
}


class CallResultNaming(ClinicNamingBase):
    """
    Detects variables that store function call results and names them
    based on the called function.
    """

    PRIORITY = 60  # After loop counters, before generic patterns

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._result_vars: dict[SimVariable, str] = {}  # var -> suggested name

    def analyze(self) -> dict[SimVariable, str]:
        """
        Analyze the graph for function call result patterns.

        :return: Dictionary mapping SimVariable to new name
        """
        if not self._graph:
            return {}

        # Find all variables that receive function call results
        self._find_call_results()

        # Convert to var_to_new_name
        self._var_to_new_name = dict(self._result_vars)

        return self._var_to_new_name

    def _find_call_results(self) -> None:
        """
        Find variables that store function call results.
        """
        for node in self._graph:
            if not isinstance(node, ailment.Block):
                continue

            for stmt in node.statements:
                # Look for Call statements with return values
                if isinstance(stmt, Call):
                    self._analyze_call(stmt)

                # Look for assignments where src is a call
                elif isinstance(stmt, Assignment) and isinstance(stmt.src, Call):
                    self._analyze_call_assignment(stmt)

    def _analyze_call(self, call: Call) -> None:
        """
        Analyze a Call statement for its return value.
        """
        if call.ret_expr is None:
            return

        # Get the variable storing the result
        var = self._get_linked_variable(call.ret_expr)
        if var is None:
            return

        # Get the function name
        func_name = self._get_function_name(call)
        if func_name is None:
            return

        # Check if we have a naming rule for this function
        suggested_name = self._get_name_for_function(func_name)
        if suggested_name:
            self._record_result_var(var, suggested_name)

    def _analyze_call_assignment(self, stmt: Assignment) -> None:
        """
        Analyze an assignment where the source is a function call.
        """
        call = stmt.src
        if not isinstance(call, Call):
            return

        # Get the variable being assigned to
        var = self._get_linked_variable(stmt.dst)
        if var is None:
            return

        # Get the function name
        func_name = self._get_function_name(call)
        if func_name is None:
            return

        # Check if we have a naming rule for this function
        suggested_name = self._get_name_for_function(func_name)
        if suggested_name:
            self._record_result_var(var, suggested_name)

    @staticmethod
    def _get_name_for_function(func_name: str) -> str | None:
        """
        Get the suggested variable name for a function's result.
        """

        # Normalize the function name
        normalized = func_name.lower().strip("_")

        # Check for exact match
        if normalized in FUNCTION_RESULT_NAMES:
            return FUNCTION_RESULT_NAMES[normalized]

        # Check for partial matches (e.g., __malloc -> malloc)
        for pattern, name in FUNCTION_RESULT_NAMES.items():
            if pattern in normalized:
                return name

        return None

    def _record_result_var(self, var: SimVariable, suggested_name: str) -> None:
        """
        Record a variable as a function result.
        """
        # Don't overwrite if already recorded with a name
        if var not in self._result_vars:
            self._result_vars[var] = suggested_name

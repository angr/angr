# pylint:disable=missing-module-docstring
"""
Semantic variable naming patterns for the decompiler.

This package provides various patterns for automatically naming variables
based on their semantic usage (loop counters, array indices, etc.).
"""
from __future__ import annotations
from .naming_base import SemanticNamingBase
from .loop_counter_naming import LoopCounterNaming
from .array_index_naming import ArrayIndexNaming
from .call_result_naming import CallResultNaming
from .size_naming import SizeNaming
from .boolean_naming import BooleanNaming
from .pointer_naming import PointerNaming
from .orchestrator import SemanticNamingOrchestrator, NAMING_PATTERNS

__all__ = [
    "NAMING_PATTERNS",
    "ArrayIndexNaming",
    "BooleanNaming",
    "CallResultNaming",
    "LoopCounterNaming",
    "PointerNaming",
    "SemanticNamingBase",
    "SemanticNamingOrchestrator",
    "SizeNaming",
]

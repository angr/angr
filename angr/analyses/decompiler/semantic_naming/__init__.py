# pylint:disable=missing-module-docstring
"""
Semantic variable naming patterns for the decompiler.

This package provides various patterns for automatically naming variables
based on their semantic usage (loop counters, array indices, etc.).

The naming passes are split into two categories:
- Clinic-based passes: Run on the AIL graph before structuring (ClinicNamingBase)
- Region-based passes: Run after structuring on the structured region (RegionNamingBase)

Loop counter naming is a Region-based pass that runs in RegionSimplifier to
leverage the structured LoopNode information.
"""

from __future__ import annotations

from .array_index_naming import ArrayIndexNaming
from .boolean_naming import BooleanNaming
from .call_result_naming import CallResultNaming
from .naming_base import ClinicNamingBase, RegionNamingBase, SemanticNamingBase
from .orchestrator import NAMING_PATTERNS, SemanticNamingOrchestrator
from .pointer_naming import PointerNaming
from .region_loop_counter_naming import RegionLoopCounterNaming
from .size_naming import SizeNaming

__all__ = [
    "NAMING_PATTERNS",
    "ArrayIndexNaming",
    "BooleanNaming",
    "CallResultNaming",
    "ClinicNamingBase",
    "PointerNaming",
    "RegionLoopCounterNaming",
    "RegionNamingBase",
    "SemanticNamingBase",
    "SemanticNamingOrchestrator",
    "SizeNaming",
]

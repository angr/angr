# Compatibility shim: these helpers live in angr.utils.ail now.
from __future__ import annotations

from angr.utils.ail import (
    CallFinder,
    CallVisitor,
    deref_vvar_and_offset,
    extract_vvar_and_offset,
    find_call,
    get_terminal_call,
    has_call,
    unwrap_combo_reg_vvar_reference,
    unwrap_stack_vvar_reference,
    unwrap_stack_vvar_reference_with_offset,
)

__all__ = [
    "CallFinder",
    "CallVisitor",
    "deref_vvar_and_offset",
    "extract_vvar_and_offset",
    "find_call",
    "get_terminal_call",
    "has_call",
    "unwrap_combo_reg_vvar_reference",
    "unwrap_stack_vvar_reference",
    "unwrap_stack_vvar_reference_with_offset",
]

"""
Knowledge-base edits for decompilation output: renaming, retyping, and commenting.

This layer is deliberately free of any UI or transport dependency so both the headless MCP server
and angr-management drive the same code. It is *not* thread-safe: locking belongs to whoever owns
the knowledge base's lifetime.
"""

from __future__ import annotations

from .cache import (
    DEFAULT_FLAVOR,
    get_cache,
    invalidate,
    require_cache,
    restore_user_edits,
    snapshot_user_edits,
)
from .errors import (
    AmbiguousFunctionError,
    DecompilationEditError,
    FunctionNotFoundError,
    InvalidNameError,
    NameCollisionError,
    NotDecompiledError,
    TypeParseError,
    UnsupportedEditError,
    VariableNotFoundError,
)
from .hooks import EditHooks, NullEditHooks

__all__ = [
    "DEFAULT_FLAVOR",
    "AmbiguousFunctionError",
    "DecompilationEditError",
    "EditHooks",
    "FunctionNotFoundError",
    "InvalidNameError",
    "NameCollisionError",
    "NotDecompiledError",
    "NullEditHooks",
    "TypeParseError",
    "UnsupportedEditError",
    "VariableNotFoundError",
    "get_cache",
    "invalidate",
    "require_cache",
    "restore_user_edits",
    "snapshot_user_edits",
]

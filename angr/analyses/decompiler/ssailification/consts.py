from __future__ import annotations

# Every byte of a stack variable's extent costs an entry in the traversal state's
# stackvar_bases and stackvar_defs maps, so this bound is a memory limit.
MAX_STACK_VAR_SIZE = 64 * 1024


__all__ = ("MAX_STACK_VAR_SIZE",)

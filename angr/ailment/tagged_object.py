"""Typing helpers for the ``.tags`` mapping on AIL objects."""

from __future__ import annotations

from typing import TypedDict


class TagDict(TypedDict, total=False):
    """Schema for the ``.tags`` mapping on AIL data classes.

    Only primitive-valued tags survive the Rust port. ``reg_vvars`` was
    promoted to a dedicated field on ``VirtualVariable``. Variable
    information (``variable``, ``variable_offset``, ``reference_*``) now
    lives in a side :class:`VariableMap` (see
    ``angr.analyses.decompiler.variable_map``).
    """

    always_propagate: bool
    block_idx: int
    deref_src_addr: int
    extra_def: bool
    extra_defs: list[int]
    ins_addr: int
    is_prototype_guessed: bool
    keep_in_slice: bool
    orig_ins_addr: int
    reg_name: str
    uninitialized: bool
    vex_block_addr: int
    vex_stmt_idx: int
    write_size: int
    outlining_artifact: bool


__all__ = ["TagDict"]

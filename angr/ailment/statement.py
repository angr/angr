"""Shim re-exporting the Rust Statement classes.

Phase D pivot: every concrete Statement "subclass" is now a Python
marker class whose ``__new__`` calls a factory on the single
``Statement`` rustlib pyclass. The markers live in
``angr.ailment._phase_d_stmt_spike`` and dispatch via metaclass
``__instancecheck__`` on the inner variant tag. This module re-exports
them so existing import paths continue to work.
"""

from __future__ import annotations

from angr.ailment._phase_d_stmt_spike import (
    CAS,
    Assignment,
    ConditionalJump,
    DirtyStatement,
    Jump,
    Label,
    Return,
    SideEffectStatement,
    Store,
    WeakAssignment,
)

from .tagged_object import TaggedObject  # re-export for backward compat


class _StatementMeta(type):
    _MEMBERS = (
        Assignment,
        WeakAssignment,
        Store,
        Jump,
        ConditionalJump,
        SideEffectStatement,
        Return,
        CAS,
        DirtyStatement,
        Label,
    )

    def __instancecheck__(cls, instance):
        if cls.__dict__.get("_is_statement_marker"):
            return isinstance(instance, cls._MEMBERS)
        return type.__instancecheck__(cls, instance)

    def __subclasscheck__(cls, subclass):
        if cls.__dict__.get("_is_statement_marker"):
            return subclass is cls or issubclass(subclass, cls._MEMBERS)
        return type.__subclasscheck__(cls, subclass)


class Statement(metaclass=_StatementMeta):
    """Backward-compatibility marker for ``isinstance(x, Statement)``."""

    _is_statement_marker = True

    def __init__(self, idx=None, *_extra, **tags):
        self.idx = idx
        self.tags = tags

    @staticmethod
    def from_bytes(data: bytes):
        """Deserialize a Statement from bytes."""
        from angr.rustylib.ailment import Statement as _PhaseD

        return _PhaseD.from_bytes(data)


__all__ = [
    "CAS",
    "Assignment",
    "ConditionalJump",
    "DirtyStatement",
    "Jump",
    "Label",
    "Return",
    "SideEffectStatement",
    "Statement",
    "Store",
    "TaggedObject",
    "WeakAssignment",
]

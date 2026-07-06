"""Shim re-exporting the Rust Statement classes.

Phase D pivot: every concrete Statement "subclass" is now a Python
marker class whose ``__new__`` calls a factory on the single
``Statement`` rustlib pyclass. The markers live in
``angr.ailment._phase_d_stmt_spike`` and dispatch via metaclass
``__instancecheck__`` on the inner variant tag. This module re-exports
them so existing import paths continue to work.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .tagged_object import TaggedObject  # re-export for backward compat

if TYPE_CHECKING:
    # Static typing story: at runtime every marker below produces (and
    # every ``isinstance`` matches) ``angr.rustylib.ailment.Statement``
    # instances -- the marker classes never appear in an instance's MRO.
    # For the type checker each marker name therefore *is* the Statement
    # pyclass; annotations like ``-> Assignment`` mean "a Statement whose
    # variant is Assignment" and all variant accessors come from the
    # Statement stub.
    from angr.rustylib.ailment import (  # pylint:disable=import-error,no-name-in-module
        Statement,
    )
    from angr.rustylib.ailment import (
        Statement as Assignment,
    )
    from angr.rustylib.ailment import (
        Statement as CAS,
    )
    from angr.rustylib.ailment import (
        Statement as ConditionalJump,
    )
    from angr.rustylib.ailment import (
        Statement as DirtyStatement,
    )
    from angr.rustylib.ailment import (
        Statement as Jump,
    )
    from angr.rustylib.ailment import (
        Statement as Label,
    )
    from angr.rustylib.ailment import (
        Statement as NoOp,
    )
    from angr.rustylib.ailment import (
        Statement as Return,
    )
    from angr.rustylib.ailment import (
        Statement as SideEffectStatement,
    )
    from angr.rustylib.ailment import (
        Statement as Store,
    )
    from angr.rustylib.ailment import (
        Statement as WeakAssignment,
    )
else:
    from angr.ailment._phase_d_stmt_spike import (
        CAS,
        Assignment,
        ConditionalJump,
        DirtyStatement,
        Jump,
        Label,
        NoOp,
        Return,
        SideEffectStatement,
        Store,
        WeakAssignment,
    )

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
            NoOp,
        )

        def __instancecheck__(cls, instance):
            if cls.__dict__.get("_is_statement_marker"):
                # Union of the variant markers, plus normal MRO dispatch so
                # pure-Python subclasses of the marker (e.g. the structurer's
                # IncompleteSwitchCaseHeadStatement) still match.
                return isinstance(instance, cls._MEMBERS) or type.__instancecheck__(cls, instance)
            return type.__instancecheck__(cls, instance)

        def __subclasscheck__(cls, subclass):
            if cls.__dict__.get("_is_statement_marker"):
                return subclass is cls or issubclass(subclass, cls._MEMBERS)
            return type.__subclasscheck__(cls, subclass)

    class Statement(metaclass=_StatementMeta):
        """Backward-compatibility marker for ``isinstance(x, Statement)``."""

        _is_statement_marker = True

        def __init__(self, idx=None, *_extra, **tags):  # pylint:disable=keyword-arg-before-vararg
            self.idx = idx
            self.tags = tags

        @staticmethod
        def from_bytes(data: bytes):
            """Deserialize a Statement from bytes."""
            from angr.rustylib.ailment import (  # pylint:disable=import-error,import-outside-toplevel
                Statement as _PhaseD,
            )

            return _PhaseD.from_bytes(data)


__all__ = [
    "CAS",
    "Assignment",
    "ConditionalJump",
    "DirtyStatement",
    "Jump",
    "Label",
    "NoOp",
    "Return",
    "SideEffectStatement",
    "Statement",
    "Store",
    "TaggedObject",
    "WeakAssignment",
]

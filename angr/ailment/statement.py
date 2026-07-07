"""AIL Statement classes.

Mirror of ``angr.ailment.expression`` for the Statement side. AIL
statement instances are ``angr.rustylib.ailment.Statement`` -- a single
Rust pyclass wrapping the ``AilStatement`` fat enum. The per-variant
classes in this module (``Assignment``, ``Store``, ...) are Python-side
marker classes whose ``__new__`` calls a ``Statement._new_*`` factory
and returns a ``Statement`` instance whose ``__class__`` is
``Statement`` (not the marker); ``isinstance`` dispatches on the
variant tag via metaclass. For static type checkers each marker name
is aliased to the ``Statement`` pyclass itself (see the
``TYPE_CHECKING`` branch).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

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
    from angr.rustylib.ailment import Statement as _Statement  # pylint:disable=import-error
    from angr.rustylib.ailment import StatementKind as SK  # pylint:disable=import-error

    class _AilStmtMarkerMeta(type):
        """Metaclass for the Statement marker classes.

        ``_kind`` (class attr) is the variant tag this marker matches.
        ``__instancecheck__`` returns True iff the instance is a
        ``Statement`` whose ``kind`` matches.

        ``_kinds`` is an optional frozenset for markers that match a union
        of variants (e.g. an abstract ``Statement`` parent marker).
        """

        _kind: SK
        _kinds: frozenset[SK]
        _match_kinds: frozenset[SK]
        _match_kind_ints: frozenset[int]
        _match_kind_int_single: int | None

        def __init__(cls, name, bases, namespace, **kwargs):
            super().__init__(name, bases, namespace, **kwargs)
            # See ``expression._AilMarkerMeta.__init__`` for rationale.
            kinds = namespace.get("_kinds")
            if kinds is None:
                kind = namespace.get("_kind")
                if kind is not None:
                    cls._match_kinds = frozenset({kind})
            else:
                cls._match_kinds = kinds if isinstance(kinds, frozenset) else frozenset(kinds)
            # Mirror as a plain-int frozenset; see
            # ``expression._AilMarkerMeta`` for rationale.
            if hasattr(cls, "_match_kinds"):
                cls._match_kind_ints = frozenset(int(k) for k in cls._match_kinds)
                cls._match_kind_int_single = (
                    next(iter(cls._match_kind_ints)) if len(cls._match_kind_ints) == 1 else None
                )

        def __instancecheck__(cls, instance: Any) -> bool:
            # ``type(x) is`` (final pyclass) + direct int compare for
            # single-kind markers; see ``expression._AilMarkerMeta``.
            if type(instance) is not _Statement:
                return False
            k = cls._match_kind_int_single
            if k is not None:
                return instance.pykind == k
            return instance.pykind in cls._match_kind_ints

        def __subclasscheck__(cls, subclass: type) -> bool:
            return subclass is cls

        def __call__(cls, *args, **kwargs):
            # Normalize ``idx=None`` to 0 -- the constructors accept
            # ``Optional[int]`` for ``idx`` while the fat-enum factories use
            # plain ``i64``.
            if args and args[0] is None:
                args = (0, *args[1:])
            return type.__call__(cls, *args, **kwargs)

    class Assignment(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Assignment``."""

        _kind = SK.Assignment

        def __new__(cls, idx, dst, src, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_assignment(idx, dst, src, **tags)

    class WeakAssignment(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``WeakAssignment``."""

        _kind = SK.WeakAssignment

        def __new__(cls, idx, dst, src, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_weak_assignment(idx, dst, src, **tags)

    class Label(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Label``."""

        _kind = SK.Label

        def __new__(cls, idx, name, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_label(idx, name, **tags)

    class Store(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Store``."""

        _kind = SK.Store

        def __new__(  # type: ignore[misc]
            cls,
            idx,
            addr,
            data,
            size,
            endness,
            guard=None,
            **tags,
        ) -> _Statement:
            return _Statement._new_store(idx, addr, data, size, endness, guard=guard, **tags)

    class Jump(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Jump``."""

        _kind = SK.Jump

        def __new__(cls, idx, target, target_idx=None, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_jump(idx, target, target_idx=target_idx, **tags)

    class ConditionalJump(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``ConditionalJump``."""

        _kind = SK.ConditionalJump

        def __new__(  # type: ignore[misc]
            cls,
            idx,
            condition,
            true_target,
            false_target,
            *,
            true_target_idx=None,
            false_target_idx=None,
            **tags,
        ) -> _Statement:
            return _Statement._new_conditional_jump(
                idx,
                condition,
                true_target,
                false_target,
                true_target_idx=true_target_idx,
                false_target_idx=false_target_idx,
                **tags,
            )

    class SideEffectStatement(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``SideEffectStatement``."""

        _kind = SK.SideEffectStatement

        def __new__(  # type: ignore[misc]
            cls,
            idx,
            expr,
            ret_expr=None,
            fp_ret_expr=None,
            **tags,
        ) -> _Statement:
            return _Statement._new_side_effect_statement(idx, expr, ret_expr=ret_expr, fp_ret_expr=fp_ret_expr, **tags)

    class Return(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Return``."""

        _kind = SK.Return

        def __new__(cls, idx, ret_exprs, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_return(idx, ret_exprs, **tags)

    class CAS(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``CAS``."""

        _kind = SK.CAS

        def __new__(  # type: ignore[misc]
            cls,
            idx,
            addr,
            data_lo,
            data_hi,
            expd_lo,
            expd_hi,
            old_lo,
            old_hi,
            endness,
            **tags,
        ) -> _Statement:
            return _Statement._new_cas(idx, addr, data_lo, data_hi, expd_lo, expd_hi, old_lo, old_hi, endness, **tags)

    class DirtyStatement(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``DirtyStatement``."""

        _kind = SK.DirtyStatement

        def __new__(cls, idx, dirty, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_dirty_statement(idx, dirty, **tags)

    class NoOp(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``NoOp``.

        Placeholder for a removed statement; defines and uses no atoms.
        Primarily used by the AIL simplifier's dead-assignment removal
        so the indices of surrounding statements stay stable until the
        block is compacted.
        """

        _kind = SK.NoOp

        def __new__(cls, idx, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_no_op(idx, **tags)

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
        """Marker for ``isinstance(x, Statement)`` checks."""

        _is_statement_marker = True

        def __init__(self, idx=None, *_extra, **tags):  # pylint:disable=keyword-arg-before-vararg
            self.idx = idx
            self.tags = tags

        @staticmethod
        def from_bytes(data: bytes):
            """Deserialize a Statement from bytes."""
            from angr.rustylib.ailment import (  # pylint:disable=import-error,import-outside-toplevel
                Statement as _RustStatement,
            )

            return _RustStatement.from_bytes(data)


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

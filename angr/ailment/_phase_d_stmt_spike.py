"""Phase D spike: Python marker classes for AIL Statements.

Mirror of ``angr.ailment._phase_d_spike`` for the Statement side. The
real class is a single ``Statement`` ``#[pyclass]`` wrapping the
``AilStatement`` fat enum on the Rust side; per-variant markers here
override ``__new__`` to produce ``Statement`` instances whose
``__class__`` is ``Statement`` (not the marker).

This module is spike-only: the bulk migration moves these into the
canonical ``angr.ailment.statement`` module and drops the legacy
per-class rustlib Statement pyclasses.
"""

from __future__ import annotations

from typing import Any

from angr.rustylib.ailment import Statement as _Statement


class _AilStmtMarkerMeta(type):
    """Metaclass for Phase D Statement marker classes.

    ``_kind`` (class attr) is the variant tag this marker matches.
    ``__instancecheck__`` returns True iff the instance is a
    ``Statement`` whose ``kind`` matches.

    ``_kinds`` is an optional frozenset for markers that match a union
    of variants (e.g. an abstract ``Statement`` parent marker).
    """

    _kind: str
    _kinds: frozenset[str]
    _match_kinds: frozenset[str]

    def __init__(cls, name, bases, namespace, **kwargs):
        super().__init__(name, bases, namespace, **kwargs)
        # See ``_AilMarkerMeta.__init__`` for rationale.
        kinds = namespace.get("_kinds")
        if kinds is None:
            kind = namespace.get("_kind")
            if kind is not None:
                cls._match_kinds = frozenset({kind})
        else:
            cls._match_kinds = kinds if isinstance(kinds, frozenset) else frozenset(kinds)

    def __instancecheck__(cls, instance: Any) -> bool:
        return isinstance(instance, _Statement) and instance.kind in cls._match_kinds

    def __subclasscheck__(cls, subclass: type) -> bool:
        return subclass is cls

    def __call__(cls, *args, **kwargs):
        # Normalize ``idx=None`` to 0 -- legacy pyclasses accepted
        # ``Optional[int]`` via the ``Idx`` newtype that defaulted to 0.
        if args and args[0] is None:
            args = (0, *args[1:])
        return type.__call__(cls, *args, **kwargs)


class Assignment(metaclass=_AilStmtMarkerMeta):
    """Marker for ``Statement`` instances whose variant is ``Assignment``."""

    _kind = "Assignment"

    def __new__(cls, idx, dst, src, **tags) -> _Statement:  # type: ignore[misc]
        return _Statement._new_assignment(idx, dst, src, **tags)


class WeakAssignment(metaclass=_AilStmtMarkerMeta):
    """Marker for ``Statement`` instances whose variant is ``WeakAssignment``."""

    _kind = "WeakAssignment"

    def __new__(cls, idx, dst, src, **tags) -> _Statement:  # type: ignore[misc]
        return _Statement._new_weak_assignment(idx, dst, src, **tags)


class Label(metaclass=_AilStmtMarkerMeta):
    """Marker for ``Statement`` instances whose variant is ``Label``."""

    _kind = "Label"

    def __new__(cls, idx, name, **tags) -> _Statement:  # type: ignore[misc]
        return _Statement._new_label(idx, name, **tags)


class Store(metaclass=_AilStmtMarkerMeta):
    """Marker for ``Statement`` instances whose variant is ``Store``."""

    _kind = "Store"

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

    _kind = "Jump"

    def __new__(cls, idx, target, target_idx=None, **tags) -> _Statement:  # type: ignore[misc]
        return _Statement._new_jump(idx, target, target_idx=target_idx, **tags)


class ConditionalJump(metaclass=_AilStmtMarkerMeta):
    """Marker for ``Statement`` instances whose variant is ``ConditionalJump``."""

    _kind = "ConditionalJump"

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

    _kind = "SideEffectStatement"

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

    _kind = "Return"

    def __new__(cls, idx, ret_exprs, **tags) -> _Statement:  # type: ignore[misc]
        return _Statement._new_return(idx, ret_exprs, **tags)


class CAS(metaclass=_AilStmtMarkerMeta):
    """Marker for ``Statement`` instances whose variant is ``CAS``."""

    _kind = "CAS"

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

    _kind = "DirtyStatement"

    def __new__(cls, idx, dirty, **tags) -> _Statement:  # type: ignore[misc]
        return _Statement._new_dirty_statement(idx, dirty, **tags)


__all__ = [
    "CAS",
    "Assignment",
    "ConditionalJump",
    "DirtyStatement",
    "Jump",
    "Label",
    "Return",
    "SideEffectStatement",
    "Store",
    "WeakAssignment",
]

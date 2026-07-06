"""``TaggedObject`` -- Python-side marker for the legacy
``isinstance(x, TaggedObject)`` checks.

Phase D collapsed every concrete Expression / Statement subclass into a
single ``Expression`` / ``Statement`` pyclass on the Rust side. There's
no longer a per-class hierarchy to union over -- ``isinstance(x,
TaggedObject)`` is equivalent to "``x`` is one of the Phase D pyclasses".
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, TypedDict

from angr.rustylib.ailment import Expression, Statement  # pylint:disable=import-error


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


class _TaggedObjectMeta(type):
    """``isinstance(x, TaggedObject)`` matches any Phase D Expression /
    Statement instance."""

    _MEMBERS = (Expression, Statement)

    def __instancecheck__(cls, instance: Any) -> bool:
        # Union of the Phase D pyclasses, plus normal MRO dispatch so
        # pure-Python subclasses of the compat markers still match.
        return isinstance(instance, cls._MEMBERS) or type.__instancecheck__(cls, instance)

    def __subclasscheck__(cls, subclass: type) -> bool:
        return issubclass(subclass, cls._MEMBERS) or subclass is cls


class TaggedObject(metaclass=_TaggedObjectMeta):
    """Marker class for backward-compatible ``isinstance(x, TaggedObject)`` checks.

    The real hierarchy has no shared base anymore; this class only exists so
    legacy isinstance checks keep returning the same result.

    Some legacy code does ``__hash__ = ailment.statement.TaggedObject.__hash__``
    to opt in to the cached-hash machinery. We expose a pure-Python ``__hash__``
    here so that idiom keeps working.
    """

    if TYPE_CHECKING:
        # Provided by the matching instances at runtime: the rustlib
        # Expression / Statement pyclasses and the pure-Python marker
        # subclasses all carry ``idx`` / ``tags``; subclasses that opt
        # into the cached-hash machinery define ``_hash_core``. The
        # ``__init__`` mirrors the compat markers' ``(idx, **tags)``
        # constructor for pure-Python subclasses typed against this base.
        idx: int
        tags: Any

        def __init__(self, idx: int | None = None, *args: Any, **tags: Any) -> None: ...
        def _hash_core(self) -> int: ...

    def __hash__(self) -> int:
        """Pure-Python cached-hash dispatcher used by Python-side classes
        that subclass the Statement / Expression markers (e.g.
        ``IncompleteSwitchCaseHeadStatement``). Concrete Phase D pyclasses
        provide their own ``__hash__`` -- this one is the fallback for
        pure-Python subclasses that define ``_hash_core``."""
        cached = getattr(self, "_cached_hash", None)
        if cached is not None:
            return cached
        h = self._hash_core()  # pylint:disable=no-member
        # Classes with ``__slots__`` that don't reserve ``_cached_hash``
        # fall through without caching.
        with contextlib.suppress(AttributeError):
            self._cached_hash = h  # pylint:disable=attribute-defined-outside-init
        return h


__all__ = ["TagDict", "TaggedObject"]

"""Phase D spike: Python marker classes over the new ``Expression`` pyclass.

This module is *spike-only*. It demonstrates how the marker / metaclass
pattern works against the new ``Expression`` Rust pyclass for three
representative variants (``Const``, ``BinaryOp``, ``Load``). The full
migration moves these into the canonical ``angr.ailment.expression``
module and replaces the existing per-class re-exports.

Design:

* ``Const`` etc. are marker classes whose ``__new__`` calls one of the
  ``Expression._new_*`` staticmethods and returns the resulting
  ``Expression`` instance. The caller writes ``Const(0, None, 42, 64)``
  but the value's ``__class__`` is ``Expression`` -- the marker doesn't
  participate in the instance.

* A metaclass on each marker makes ``isinstance(c, Const)`` work by
  dispatching on ``Expression.kind``. The ``_AilMarkerMeta`` checks the
  variant tag rather than walking the MRO.

* Python-side subclassing of these markers is *not supported* (see
  the metaclass: ``__subclasscheck__`` only matches the marker itself).
  An audit confirmed no in-tree subclasses; the codebase prefers the
  factory pattern.
"""

from __future__ import annotations

from typing import Any

from angr.rustylib.ailment import ConvertType as _ConvertType
from angr.rustylib.ailment import Expression as _Expression
from angr.rustylib.ailment import ExpressionKind as EK


class _AilMarkerMeta(type):
    """Metaclass for the Phase D Expression marker classes.

    ``_kind`` (class attr) is the variant tag this marker matches.
    Most markers match a single variant; the ``Call`` and ``Macro``
    markers match a union so the legacy class-inheritance relationships
    (``Macro`` is-a ``Call``; ``FunctionLikeMacro`` is-a ``Macro``) are
    preserved at ``isinstance`` boundaries -- analyses across angr rely
    on ``isinstance(x, Call)`` being True for Macro / FunctionLikeMacro
    instances.

    ``__instancecheck__`` returns True iff the instance is an
    ``Expression`` whose ``kind`` is in ``_kinds``.
    """

    _kind: EK
    _kinds: frozenset[EK]
    _match_kinds: frozenset[EK]
    _match_kind_ints: frozenset[int]

    def __init__(cls, name, bases, namespace, **kwargs):
        super().__init__(name, bases, namespace, **kwargs)
        # Precompute the kind-match set so ``__instancecheck__`` can do a
        # single set-membership test instead of two ``getattr`` calls per
        # check. Hot in the decompiler (~1.1M marker isinstance() calls
        # per ``Decompiler(doit)``).
        kinds = namespace.get("_kinds")
        if kinds is None:
            kind = namespace.get("_kind")
            if kind is not None:
                cls._match_kinds = frozenset({kind})
        else:
            cls._match_kinds = kinds if isinstance(kinds, frozenset) else frozenset(kinds)
        # Mirror the match set as a frozenset of plain ints so
        # ``__instancecheck__`` can do the membership test against
        # ``instance.pykind`` (a cached ``Py<int>``) -- this skips the
        # ``ExpressionKind`` pyclass allocation that ``instance.kind``
        # otherwise mints on every read.
        if hasattr(cls, "_match_kinds"):
            cls._match_kind_ints = frozenset(int(k) for k in cls._match_kinds)

    def __instancecheck__(cls, instance: Any) -> bool:
        # ``isinstance(x, Expression)`` (the rustlib class) goes through
        # the normal type machinery; only the marker classes use the
        # variant-tag dispatch.
        return isinstance(instance, _Expression) and instance.pykind in cls._match_kind_ints

    def __subclasscheck__(cls, subclass: type) -> bool:
        # Markers don't support being subclassed. Reflexive equality
        # only -- ``issubclass(cls, cls)`` is True, anything else False.
        return subclass is cls

    def __call__(cls, *args, **kwargs):
        # Normalize ``idx=None`` to 0 -- legacy pyclasses accepted ``Optional[int]``
        # via the ``Idx`` newtype that defaults to 0 when given ``None``.
        # The fat-enum factories use plain ``i64`` and need explicit coercion
        # here; doing it once in the metaclass keeps the per-marker ``__new__``
        # bodies clean.
        if args and args[0] is None:
            args = (0, *args[1:])
        return type.__call__(cls, *args, **kwargs)


class Const(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Const``.

    ``Const(idx, value, bits, **tags)`` returns an ``Expression`` --
    the marker class is not in the instance's MRO.
    """

    _kind = EK.Const

    def __new__(cls, idx, value, bits, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_const(idx, value, bits, **tags)


class Tmp(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Tmp``."""

    _kind = EK.Tmp

    def __new__(cls, idx, tmp_idx, bits, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_tmp(idx, tmp_idx, bits, **tags)


class Register(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Register``."""

    _kind = EK.Register

    def __new__(cls, idx, reg_offset, bits, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_register(idx, reg_offset, bits, **tags)


class ComboRegister(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``ComboRegister``."""

    _kind = EK.ComboRegister

    def __new__(cls, idx, registers, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_combo_register(idx, registers, **tags)


class Phi(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Phi``."""

    _kind = EK.Phi

    def __new__(cls, idx, bits, src_and_vvars, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_phi(idx, bits, src_and_vvars, **tags)


class VirtualVariable(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``VirtualVariable``."""

    _kind = EK.VirtualVariable

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        varid,
        bits,
        category,
        oident=None,
        reg_vvars=None,
        **tags,
    ) -> _Expression:
        return _Expression._new_virtual_variable(
            idx,
            varid,
            bits,
            category,
            oident=oident,
            reg_vvars=reg_vvars,
            **tags,
        )


class UnaryOp(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``UnaryOp``."""

    _kind = EK.UnaryOp

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        op,
        operand,
        bits=None,
        **tags,
    ) -> _Expression:
        return _Expression._new_unary_op(idx, op, operand, bits=bits, **tags)


class Convert(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Convert``."""

    _kind = EK.Convert

    # Class-level sentinels mirroring the legacy per-class pyclass.
    # Analyses test ``expr.from_type == Convert.TYPE_INT`` so these need
    # to live on the marker class.
    TYPE_INT = _ConvertType.TYPE_INT
    TYPE_FP = _ConvertType.TYPE_FP

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        from_bits,
        to_bits,
        is_signed,
        operand,
        from_type=None,
        to_type=None,
        rounding_mode=None,
        **tags,
    ) -> _Expression:
        return _Expression._new_convert(
            idx,
            from_bits,
            to_bits,
            is_signed,
            operand,
            from_type=from_type,
            to_type=to_type,
            rounding_mode=rounding_mode,
            **tags,
        )


class Reinterpret(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Reinterpret``."""

    _kind = EK.Reinterpret

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        from_bits,
        from_type,
        to_bits,
        to_type,
        operand,
        **tags,
    ) -> _Expression:
        return _Expression._new_reinterpret(idx, from_bits, from_type, to_bits, to_type, operand, **tags)


# Master's ``BinaryOp.__init__`` derives ``bits`` from ``op`` when callers
# don't pass one explicitly (CmpEQ/Not/LogicalOr/... are 1-bit, Carry is
# 8-bit, Concat is sum of operand widths, etc.). The Phase D Rust
# constructor only knows to fall back to ``operands[0].bits``, so without
# this shim a freshly-built ``BinaryOp('CmpEQ', [v8, v8])`` would end up
# 8 bits wide and downstream code treating its result as a boolean would
# break (e.g. ``condition_processor`` asserting the condition coerces to
# a claripy Bool).
_BINOP_FIXED_BITS = {
    "CmpF": 32,
    "CmpEQ": 1,
    "CmpNE": 1,
    "CmpLT": 1,
    "CmpGE": 1,
    "CmpLE": 1,
    "CmpGT": 1,
    "ExpCmpNE": 1,
    "Carry": 8,
    "SCarry": 8,
    "SBorrow": 8,
}


def _binop_bits_for(op, operands):
    fixed = _BINOP_FIXED_BITS.get(op)
    if fixed is not None:
        return fixed
    op0_bits = operands[0].bits if not isinstance(operands[0], int) else operands[1].bits
    if op == "Concat":
        return op0_bits + operands[1].bits
    if op == "Mull":
        return op0_bits * 2
    return op0_bits


class BinaryOp(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``BinaryOp``."""

    _kind = EK.BinaryOp

    # Ported from the legacy rustlib BinaryOp class attr. Analyses
    # (notably ``negate``) consult this to flip comparison ops.
    COMPARISON_NEGATION = {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpGE": "CmpLT",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
    }

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        op,
        operands,
        signed=False,
        *,
        bits=None,
        floating_point=False,
        rounding_mode=None,
        vector_count=None,
        vector_size=None,
        **tags,
    ) -> _Expression:
        if bits is None:
            bits = _binop_bits_for(op, operands)
        return _Expression._new_binary_op(
            idx,
            op,
            operands,
            signed,
            bits=bits,
            floating_point=floating_point,
            rounding_mode=rounding_mode,
            vector_count=vector_count,
            vector_size=vector_size,
            **tags,
        )


class ITE(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``ITE``."""

    _kind = EK.ITE

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        cond,
        iffalse,
        iftrue,
        **tags,
    ) -> _Expression:
        return _Expression._new_ite(idx, cond, iffalse, iftrue, **tags)


class Extract(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Extract``."""

    _kind = EK.Extract

    def __new__(cls, idx, bits, base, offset, endness, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_extract(idx, bits, base, offset, endness, **tags)


class Insert(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Insert``."""

    _kind = EK.Insert

    def __new__(cls, idx, base, offset, value, endness, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_insert(idx, base, offset, value, endness, **tags)


class StringLiteral(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``StringLiteral``."""

    _kind = EK.StringLiteral

    def __new__(cls, idx, data, bits, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_string_literal(idx, data, bits, **tags)


class BasePointerOffset(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``BasePointerOffset``."""

    _kind = EK.BasePointerOffset

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        bits,
        base,
        offset,
        **tags,
    ) -> _Expression:
        return _Expression._new_base_pointer_offset(idx, bits, base, offset, **tags)


class StackBaseOffset(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``StackBaseOffset``."""

    _kind = EK.StackBaseOffset

    def __new__(cls, idx, bits, offset, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_stack_base_offset(idx, bits, offset, **tags)


class Call(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Call``.

    ``isinstance`` also matches ``Macro`` / ``FunctionLikeMacro``
    instances to preserve legacy subclass relationships.
    """

    _kind = EK.Call
    _kinds = frozenset({EK.Call, EK.Macro, EK.FunctionLikeMacro})

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        target,
        args=None,
        bits=None,
        arg_vvars=None,
        **tags,
    ) -> _Expression:
        return _Expression._new_call(
            idx,
            target,
            args=args,
            bits=bits,
            arg_vvars=arg_vvars,
            **tags,
        )


class Struct(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Struct``."""

    _kind = EK.Struct

    def __new__(cls, idx, name, fields, field_offsets, bits, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_struct(idx, name, fields, field_offsets, bits, **tags)


class RustEnum(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``RustEnum``."""

    _kind = EK.RustEnum

    def __new__(cls, idx, name, fields, bits, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_rust_enum(idx, name, fields, bits, **tags)


class Array(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Array``."""

    _kind = EK.Array

    def __new__(cls, idx, elements, bits, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_array(idx, elements, bits, **tags)


class Let(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Let``."""

    _kind = EK.Let

    def __new__(cls, idx, defs, src, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_let(idx, defs, src, **tags)


class Macro(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Macro`` (abstract).

    Also matches ``FunctionLikeMacro`` instances to preserve the legacy
    ``isinstance(x, Macro)`` -> True relationship.
    """

    _kind = EK.Macro
    _kinds = frozenset({EK.Macro, EK.FunctionLikeMacro})

    def __new__(cls, idx, name, delimiter="()", **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_macro(idx, name, delimiter=delimiter, **tags)


class FunctionLikeMacro(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``FunctionLikeMacro``."""

    _kind = EK.FunctionLikeMacro

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        name,
        args,
        bits=None,
        delimiter="()",
        **tags,
    ) -> _Expression:
        return _Expression._new_function_like_macro(idx, name, args, bits=bits, delimiter=delimiter, **tags)


class DirtyExpression(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``DirtyExpression``."""

    _kind = EK.DirtyExpression

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        callee,
        operands,
        *,
        guard=None,
        mfx=None,
        maddr=None,
        msize=None,
        bits,
        **tags,
    ) -> _Expression:
        return _Expression._new_dirty_expression(
            idx,
            callee,
            operands,
            guard=guard,
            mfx=mfx,
            maddr=maddr,
            msize=msize,
            bits=bits,
            **tags,
        )


class VEXCCallExpression(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``VEXCCallExpression``."""

    _kind = EK.VEXCCallExpression

    def __new__(cls, idx, callee, operands, bits, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_vex_ccall_expression(idx, callee, operands, bits, **tags)


class MultiStatementExpression(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``MultiStatementExpression``."""

    _kind = EK.MultiStatementExpression

    def __new__(cls, idx, stmts, expr, **tags) -> _Expression:  # type: ignore[misc]
        return _Expression._new_multi_statement_expression(idx, stmts, expr, **tags)


class Load(metaclass=_AilMarkerMeta):
    """Marker for ``Expression`` instances whose variant is ``Load``."""

    _kind = EK.Load

    def __new__(  # type: ignore[misc]
        cls,
        idx,
        addr,
        size,
        endness,
        *,
        guard=None,
        alt=None,
        **tags,
    ) -> _Expression:
        return _Expression._new_load(idx, addr, size, endness, guard=guard, alt=alt, **tags)


__all__ = [
    "ITE",
    "Array",
    "BasePointerOffset",
    "BinaryOp",
    "Call",
    "ComboRegister",
    "Const",
    "Convert",
    "DirtyExpression",
    "Extract",
    "FunctionLikeMacro",
    "Insert",
    "Let",
    "Load",
    "Macro",
    "MultiStatementExpression",
    "Phi",
    "Register",
    "Reinterpret",
    "RustEnum",
    "StackBaseOffset",
    "StringLiteral",
    "Struct",
    "Tmp",
    "UnaryOp",
    "VEXCCallExpression",
    "VirtualVariable",
]

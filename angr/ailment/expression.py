"""Shim re-exporting the Rust Expression classes.

Phase D pivot: every concrete Expression "subclass" is now a Python
marker class (``Const``, ``BinaryOp``, ...) whose ``__new__`` calls a
factory on the single ``Expression`` rustlib pyclass. The markers live
in ``angr.ailment._phase_d_spike`` and dispatch via metaclass
``__instancecheck__`` on the inner variant tag. This module re-exports
them so existing import paths continue to work.

``Expression`` here is itself a Python-side marker whose metaclass
matches any concrete variant -- ``isinstance(x, Expression)`` keeps
working without forcing a full audit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.rustylib.ailment import ConvertType, VirtualVariableCategory  # pylint:disable=import-error

if TYPE_CHECKING:
    # Static typing story: at runtime every marker below produces (and
    # every ``isinstance`` matches) ``angr.rustylib.ailment.Expression``
    # instances -- the marker classes never appear in an instance's MRO.
    # For the type checker each marker name therefore *is* the Expression
    # pyclass; annotations like ``-> Const`` mean "an Expression whose
    # variant is Const" and all variant accessors come from the
    # Expression stub.
    from angr.rustylib.ailment import (  # pylint:disable=import-error,no-name-in-module
        Expression,
    )
    from angr.rustylib.ailment import (
        Expression as Array,
    )
    from angr.rustylib.ailment import (
        Expression as Atom,
    )
    from angr.rustylib.ailment import (
        Expression as BasePointerOffset,
    )
    from angr.rustylib.ailment import (
        Expression as BinaryOp,
    )
    from angr.rustylib.ailment import (
        Expression as Call,
    )
    from angr.rustylib.ailment import (
        Expression as ComboRegister,
    )
    from angr.rustylib.ailment import (
        Expression as Const,
    )
    from angr.rustylib.ailment import (
        Expression as Convert,
    )
    from angr.rustylib.ailment import (
        Expression as DirtyExpression,
    )
    from angr.rustylib.ailment import (
        Expression as Extract,
    )
    from angr.rustylib.ailment import (
        Expression as FunctionLikeMacro,
    )
    from angr.rustylib.ailment import (
        Expression as ITE,
    )
    from angr.rustylib.ailment import (
        Expression as Insert,
    )
    from angr.rustylib.ailment import (
        Expression as Let,
    )
    from angr.rustylib.ailment import (
        Expression as Load,
    )
    from angr.rustylib.ailment import (
        Expression as Macro,
    )
    from angr.rustylib.ailment import (
        Expression as MultiStatementExpression,
    )
    from angr.rustylib.ailment import (
        Expression as Op,
    )
    from angr.rustylib.ailment import (
        Expression as Phi,
    )
    from angr.rustylib.ailment import (
        Expression as Register,
    )
    from angr.rustylib.ailment import (
        Expression as Reinterpret,
    )
    from angr.rustylib.ailment import (
        Expression as RustEnum,
    )
    from angr.rustylib.ailment import (
        Expression as StackBaseOffset,
    )
    from angr.rustylib.ailment import (
        Expression as StringLiteral,
    )
    from angr.rustylib.ailment import (
        Expression as Struct,
    )
    from angr.rustylib.ailment import (
        Expression as Tmp,
    )
    from angr.rustylib.ailment import (
        Expression as UnaryOp,
    )
    from angr.rustylib.ailment import (
        Expression as VEXCCallExpression,
    )
    from angr.rustylib.ailment import (
        Expression as VirtualVariable,
    )
else:
    # Per-variant markers from the Phase D spike module. These produce
    # ``Expression`` (rustlib) instances; ``isinstance(x, Const)`` dispatches
    # via the marker's metaclass on the variant tag.
    from angr.ailment._phase_d_spike import (
        ITE,
        Array,
        BasePointerOffset,
        BinaryOp,
        Call,
        ComboRegister,
        Const,
        Convert,
        DirtyExpression,
        Extract,
        FunctionLikeMacro,
        Insert,
        Let,
        Load,
        Macro,
        MultiStatementExpression,
        Phi,
        Register,
        Reinterpret,
        RustEnum,
        StackBaseOffset,
        StringLiteral,
        Struct,
        Tmp,
        UnaryOp,
        VEXCCallExpression,
        VirtualVariable,
    )

if not TYPE_CHECKING:
    # --- Expression compat shim ------------------------------------------------
    #
    # ``Expression`` is a Python-side marker whose metaclass matches any
    # concrete variant. ``isinstance(x, _MEMBERS)`` fans out to each marker's
    # own ``__instancecheck__`` (variant-tag dispatch), so the legacy
    # ``isinstance(x, Expression)`` semantics carry forward.

    class _ExpressionMeta(type):
        _MEMBERS = (
            Const,
            Tmp,
            Register,
            ComboRegister,
            VirtualVariable,
            Phi,
            UnaryOp,
            BinaryOp,
            Convert,
            Reinterpret,
            Load,
            ITE,
            Extract,
            Insert,
            Call,
            DirtyExpression,
            VEXCCallExpression,
            MultiStatementExpression,
            BasePointerOffset,
            StackBaseOffset,
            StringLiteral,
            Struct,
            RustEnum,
            Array,
            Let,
            Macro,
            FunctionLikeMacro,
        )

        def __instancecheck__(cls, instance):
            # Only the bare ``Expression`` marker uses the union check.
            # Subclassing the marker is rare but should fall back to normal
            # MRO -- otherwise a sibling-type instance would falsely match
            # simply because it appears in ``_MEMBERS``.
            if cls.__dict__.get("_is_expression_marker"):
                # Union of the variant markers, plus normal MRO dispatch so
                # pure-Python subclasses of the marker still match.
                return isinstance(instance, cls._MEMBERS) or type.__instancecheck__(cls, instance)
            return type.__instancecheck__(cls, instance)

        def __subclasscheck__(cls, subclass):
            if cls.__dict__.get("_is_expression_marker"):
                return subclass is cls or issubclass(subclass, cls._MEMBERS)
            return type.__subclasscheck__(cls, subclass)

    class Expression(metaclass=_ExpressionMeta):  # pylint:disable=function-redefined
        """Backward-compatibility marker for ``isinstance(x, Expression)``.

        Real AIL expression instances are ``angr.rustylib.ailment.Expression``
        (a single fat-enum pyclass). The per-variant markers (Const,
        BinaryOp, ...) dispatch on the variant tag via metaclass
        ``__instancecheck__``.
        """

        _is_expression_marker = True

        def __init__(self, idx=None, *_extra, **tags):  # pylint:disable=keyword-arg-before-vararg
            # Pure-Python subclasses of the marker (e.g. some structurer
            # helpers) call ``super().__init__(idx, **kwargs)`` and expect
            # those attributes to be readable afterwards.
            self.idx = idx
            self.tags = tags

        @staticmethod
        def from_bytes(data: bytes):
            """Deserialize an Expression from bytes."""
            from angr.rustylib.ailment import (  # pylint:disable=import-error,import-outside-toplevel
                Expression as _PhaseD,
            )

            return _PhaseD.from_bytes(data)

    class _AtomMeta(type):
        """Metaclass that makes ``isinstance(x, Atom)`` match any former atom marker."""

        _MEMBERS = (Const, Tmp, Register, ComboRegister, VirtualVariable, Phi)

        def __instancecheck__(cls, instance):
            return isinstance(instance, cls._MEMBERS)

        def __subclasscheck__(cls, subclass):
            return issubclass(subclass, cls._MEMBERS) or subclass is cls

    class Atom(metaclass=_AtomMeta):  # pylint:disable=function-redefined
        """Marker class for backward-compatible ``isinstance(x, Atom)`` checks."""

    class _OpMeta(type):
        """``isinstance(x, Op)`` matches any op-shaped expression (UnaryOp,
        BinaryOp, Convert, Reinterpret, Let)."""

        _MEMBERS = (UnaryOp, BinaryOp, Convert, Reinterpret, Let)

        def __instancecheck__(cls, instance):
            return isinstance(instance, cls._MEMBERS)

        def __subclasscheck__(cls, subclass):
            return issubclass(subclass, cls._MEMBERS) or subclass is cls

    class Op(metaclass=_OpMeta):  # pylint:disable=function-redefined
        """Marker for backward-compatible ``isinstance(x, Op)`` checks."""


def negate(expr: Expression, manager) -> Expression:
    """Negate a comparison or boolean expression -- mirrors the Python helper."""
    if isinstance(expr, UnaryOp) and expr.op == "Not":
        return expr.operand
    if isinstance(expr, BinaryOp) and expr.op in BinaryOp.COMPARISON_NEGATION:
        return BinaryOp(
            expr.idx,
            BinaryOp.COMPARISON_NEGATION[expr.op],
            expr.operands,
            signed=expr.signed,
            bits=expr.bits,
            floating_point=expr.floating_point,
            rounding_mode=expr.rounding_mode,
            **dict(expr.tags),
        )
    return UnaryOp(manager.next_atom(), "Not", expr, **dict(expr.tags))


__all__ = [
    "ITE",
    "Array",
    "Atom",
    "BasePointerOffset",
    "BinaryOp",
    "Call",
    "ComboRegister",
    "Const",
    "Convert",
    "ConvertType",
    "DirtyExpression",
    "Expression",
    "Extract",
    "FunctionLikeMacro",
    "Insert",
    "Let",
    "Load",
    "Macro",
    "MultiStatementExpression",
    "Op",
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
    "VirtualVariableCategory",
    "negate",
]

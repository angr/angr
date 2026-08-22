from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from archinfo import Endness

from angr.ailment import Expr
from angr.sim_variable import SimStackVariable

if TYPE_CHECKING:
    from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal

type SegmentedMemoryBinding = tuple[str, str, int, str | None, str | None]
type SegmentedMemoryBindings = tuple[SegmentedMemoryBinding, ...]
type SegmentedMemoryBindingMap = dict[tuple[str, str, int], tuple[str | None, str | None]]

_C_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_C_KEYWORDS = frozenset(
    {
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
        "_Alignas",
        "_Alignof",
        "_Atomic",
        "_Bool",
        "_Complex",
        "_Generic",
        "_Imaginary",
        "_Noreturn",
        "_Static_assert",
        "_Thread_local",
    }
)
_VALID_ENTRY_KEYS = frozenset({"endness", "loads", "stores"})
_VALID_ENDNESSES = frozenset({Endness.LE, Endness.BE})


def stack_offset_from_segmented_offset(expr: Expr.Expression) -> int | None:
    """Resolve a final-SSA expression that is provably the address of one recovered stack byte."""

    if isinstance(expr, Expr.StackBaseOffset):
        return expr.offset if isinstance(expr.offset, int) else None

    if isinstance(expr, Expr.UnaryOp) and expr.op == "Reference":
        operand = expr.operand
        if isinstance(operand, Expr.VirtualVariable) and (
            operand.was_stack
            or (operand.was_parameter and operand.parameter_category == Expr.VirtualVariableCategory.STACK)
        ):
            return operand.stack_offset if isinstance(operand.stack_offset, int) else None
        return None

    if isinstance(expr, Expr.Convert):
        if expr.from_bits != expr.to_bits:
            return None
        return stack_offset_from_segmented_offset(expr.operand)

    if not isinstance(expr, Expr.BinaryOp) or expr.op not in {"Add", "Sub"}:
        return None

    left, right = expr.operands
    left_offset = stack_offset_from_segmented_offset(left)
    right_offset = stack_offset_from_segmented_offset(right)
    if left_offset is not None and isinstance(right, Expr.Const) and isinstance(right.value, int):
        displacement = right.value
        if right.bits > 0 and displacement >= 1 << (right.bits - 1):
            displacement -= 1 << right.bits
        return left_offset + displacement if expr.op == "Add" else left_offset - displacement
    if expr.op == "Add" and right_offset is not None and isinstance(left, Expr.Const) and isinstance(left.value, int):
        displacement = left.value
        if left.bits > 0 and displacement >= 1 << (left.bits - 1):
            displacement -= 1 << left.bits
        return right_offset + displacement
    return None


def segmented_stack_variable(
    variable_manager: VariableManagerInternal,
    address: Expr.Expression,
    access_size: int,
) -> tuple[SimStackVariable, int] | None:
    """Find the recovered stack object named by an exact SS-based segmented access."""

    if not (
        isinstance(address, Expr.SegmentedAddress)
        and address.address_kind == "x86-protected-16:16"
        and (address.tags.get("segment_register") == "ss" or address.tags.get("segment_register_origin") == "ss")
    ):
        return None

    stack_offset = stack_offset_from_segmented_offset(address.offset)
    if stack_offset is None:
        return None

    candidates = [
        variable
        for variable in variable_manager.find_variables_by_stack_offset(stack_offset)
        if isinstance(variable, SimStackVariable)
        and isinstance(variable.offset, int)
        and isinstance(variable.size, int)
        and variable.offset <= stack_offset
        and stack_offset + access_size <= variable.offset + variable.size
    ]
    if not candidates:
        return None

    variable = min(
        candidates,
        key=lambda candidate: (
            candidate.offset != stack_offset,
            candidate.size,
            candidate.offset,
            candidate.key,
        ),
    )
    return variable, stack_offset - variable.offset


def _normalize_helpers(address_kind: str, operation: str, helpers: Any) -> dict[int, str]:
    if helpers is None:
        return {}
    if not isinstance(helpers, Mapping):
        raise TypeError(f"segmented_memory_bindings[{address_kind!r}][{operation!r}] must be a mapping")

    normalized: dict[int, str] = {}
    for size, helper in helpers.items():
        if not isinstance(size, int) or isinstance(size, bool):
            raise TypeError("segmented-memory helper widths must be integer byte counts")
        if size <= 0:
            raise ValueError("segmented-memory helper widths must be positive")
        if not isinstance(helper, str):
            raise TypeError("segmented-memory helper names must be strings")
        if _C_IDENTIFIER_RE.fullmatch(helper) is None or helper in _C_KEYWORDS:
            raise ValueError(f"Invalid C helper identifier in segmented_memory_bindings: {helper!r}")
        normalized[size] = helper
    return normalized


def normalize_segmented_memory_bindings(bindings: Mapping[str, Mapping[str, Any]] | None) -> SegmentedMemoryBindings:
    """Validate and deterministically normalize segmented-memory helper bindings.

    The input maps an AIL ``SegmentedAddress.address_kind`` to one endness and
    byte-width-indexed load/store helpers. For example::

        {
            "x86-protected-16:16": {
                "endness": "Iend_LE",
                "loads": {1: "guest_load_u8", 2: "guest_load_u16"},
                "stores": {1: "guest_store_u8", 2: "guest_store_u16"},
            }
        }

    Helpers receive ``(selector, offset)`` for loads and
    ``(selector, offset, value)`` for stores. An absent operation or width is
    intentionally unsupported; code generation never falls back to treating
    the segmented value as a native pointer.
    """

    if bindings is None:
        return ()
    if not isinstance(bindings, Mapping):
        raise TypeError("segmented_memory_bindings must be a mapping")

    normalized: list[SegmentedMemoryBinding] = []
    for address_kind, entry in bindings.items():
        if not isinstance(address_kind, str):
            raise TypeError("segmented_memory_bindings keys must be address-kind strings")
        if not address_kind or address_kind.strip() != address_kind:
            raise ValueError("segmented-memory address kinds must be non-empty and have no surrounding whitespace")
        if not isinstance(entry, Mapping):
            raise TypeError(f"segmented_memory_bindings[{address_kind!r}] must be a mapping")

        unknown_keys = set(entry) - _VALID_ENTRY_KEYS
        if unknown_keys:
            raise ValueError(f"Unknown segmented_memory_bindings keys for {address_kind!r}: {sorted(unknown_keys)!r}")

        endness = entry.get("endness")
        if endness not in _VALID_ENDNESSES:
            raise ValueError(
                f"segmented_memory_bindings[{address_kind!r}]['endness'] must be {Endness.LE!r} or {Endness.BE!r}"
            )
        loads = _normalize_helpers(address_kind, "loads", entry.get("loads"))
        stores = _normalize_helpers(address_kind, "stores", entry.get("stores"))
        if not loads and not stores:
            raise ValueError(f"segmented_memory_bindings[{address_kind!r}] must bind at least one load or store")

        for size in sorted(loads.keys() | stores.keys()):
            normalized.append((address_kind, endness, size, loads.get(size), stores.get(size)))

    return tuple(sorted(normalized, key=lambda binding: (binding[0], binding[1], binding[2])))


def segmented_memory_binding_map(bindings: SegmentedMemoryBindings) -> SegmentedMemoryBindingMap:
    return {
        (address_kind, endness, size): (load_helper, store_helper)
        for address_kind, endness, size, load_helper, store_helper in bindings
    }


__all__ = (
    "SegmentedMemoryBinding",
    "SegmentedMemoryBindingMap",
    "SegmentedMemoryBindings",
    "normalize_segmented_memory_bindings",
    "segmented_memory_binding_map",
    "segmented_stack_variable",
    "stack_offset_from_segmented_offset",
)

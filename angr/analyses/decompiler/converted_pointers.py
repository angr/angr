from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from archinfo import Arch

from .far_calls import _MAX_UINT64, _X86_PROTECTED_16_16, _normalize_register_range, _validate_c_identifier

type ConvertedPointerSelector = tuple[Literal["callsite_addr"], int]
type ConvertedPointerBinding = tuple[int, int, str, int, str, str, int, int, str, int | None, str | None]
type ConvertedPointerBindings = tuple[ConvertedPointerBinding, ...]
type ConvertedPointerBindingMap = dict[int, dict[int, tuple[str, int, str, str, int, int, str, int | None, str | None]]]


_REQUIRED_KEYS = frozenset({"helper", "span", "address_kind", "selector_register", "contract"})
_OPTIONAL_KEYS = frozenset({"native_stack_offset", "native_stack_evidence"})


def normalize_converted_pointer_bindings(
    arch: Arch,
    bindings: Mapping[ConvertedPointerSelector, Mapping[int, Mapping[str, Any]]] | None,
) -> ConvertedPointerBindings:
    """Validate exact callsite bindings for native stack-object pointer conversion.

    A row authorizes one argument at one instruction address. It does not make
    pointer-looking values native and does not bind a callee name globally. The
    C code generator must still prove that the machine value is an exact 16:16
    carrier whose offset names a completely recovered local stack interval and
    whose selector comes from the configured architectural register.  A caller
    that has independently decoded an exact machine ``LEA BP-relative; PUSH
    SS; PUSH offset`` argument may additionally seal that proof as
    ``native_stack_offset`` plus ``native_stack_evidence``.  This lets codegen
    retain the machine fact when variable unification has erased the equivalent
    high-level provenance; the live allocation and recovered storage interval
    are still checked locally.

    ``contract`` is an opaque, stable identifier for the external ABI evidence
    that supplied ``span``. It participates in cache identity so changing the
    evidence invalidates old output even when the numeric span happens to stay
    the same.
    """

    if bindings is None:
        return ()
    if not isinstance(bindings, Mapping):
        raise TypeError("converted_pointer_bindings must be a mapping")

    normalized: list[ConvertedPointerBinding] = []
    for selector, argument_bindings in bindings.items():
        if not isinstance(selector, tuple) or len(selector) != 2:
            raise TypeError("converted_pointer_bindings keys must be ('callsite_addr', instruction_address) tuples")
        selector_kind, callsite = selector
        if selector_kind != "callsite_addr":
            raise ValueError("converted_pointer_bindings only supports exact 'callsite_addr' selectors")
        if not isinstance(callsite, int) or isinstance(callsite, bool):
            raise TypeError("converted_pointer_bindings callsite addresses must be integers")
        if callsite < 0 or callsite > _MAX_UINT64:
            raise ValueError("converted_pointer_bindings callsite addresses must fit in an unsigned 64-bit integer")
        if not isinstance(argument_bindings, Mapping):
            raise TypeError(f"converted_pointer_bindings[{selector!r}] must be a mapping")
        if not argument_bindings:
            raise ValueError(f"converted_pointer_bindings[{selector!r}] must not be empty")

        for argument_index, row in argument_bindings.items():
            description = f"converted_pointer_bindings[{selector!r}][{argument_index!r}]"
            if not isinstance(argument_index, int) or isinstance(argument_index, bool):
                raise TypeError(f"{description} argument index must be an integer")
            if argument_index < 0 or argument_index > 0xFFFF:
                raise ValueError(f"{description} argument index must fit in an unsigned 16-bit integer")
            if not isinstance(row, Mapping):
                raise TypeError(f"{description} must be a mapping")
            unknown_keys = set(row) - _REQUIRED_KEYS - _OPTIONAL_KEYS
            if unknown_keys:
                raise ValueError(f"Unknown {description} keys: {sorted(unknown_keys)!r}")
            missing_keys = _REQUIRED_KEYS - set(row)
            if missing_keys:
                raise ValueError(f"Missing {description} keys: {sorted(missing_keys)!r}")

            helper = _validate_c_identifier(row["helper"], f"{description}['helper']")

            span = row["span"]
            if not isinstance(span, int) or isinstance(span, bool):
                raise TypeError(f"{description}['span'] must be an integer")
            if span <= 0 or span > 0xFFFF_FFFF:
                raise ValueError(f"{description}['span'] must fit in a positive unsigned 32-bit integer")

            address_kind = row["address_kind"]
            if not isinstance(address_kind, str):
                raise TypeError(f"{description}['address_kind'] must be a string")
            if address_kind != _X86_PROTECTED_16_16:
                raise ValueError(f"{description}['address_kind'] must be {_X86_PROTECTED_16_16!r}")

            selector_register = row["selector_register"]
            if selector_register != "ss":
                raise ValueError(f"{description}['selector_register'] must be 'ss'")
            selector_offset, selector_size = _normalize_register_range(
                arch, selector_register, f"{description}['selector_register']"
            )
            if selector_size != 2:
                raise ValueError(f"{description}['selector_register'] must be 16 bits wide")

            contract = row["contract"]
            if not isinstance(contract, str):
                raise TypeError(f"{description}['contract'] must be a string")
            if not contract or contract.strip() != contract or "\n" in contract or "\r" in contract:
                raise ValueError(f"{description}['contract'] must be a non-empty single-line identifier")

            native_stack_offset = row.get("native_stack_offset")
            native_stack_evidence = row.get("native_stack_evidence")
            if (native_stack_offset is None) != (native_stack_evidence is None):
                raise ValueError(
                    f"{description} native_stack_offset and native_stack_evidence must be supplied together"
                )
            if native_stack_offset is not None:
                if not isinstance(native_stack_offset, int) or isinstance(native_stack_offset, bool):
                    raise TypeError(f"{description}['native_stack_offset'] must be an integer")
                if native_stack_offset < -(1 << 63) or native_stack_offset >= 1 << 63:
                    raise ValueError(f"{description}['native_stack_offset'] must fit in a signed 64-bit integer")
                if native_stack_offset >= 0:
                    raise ValueError(f"{description}['native_stack_offset'] must name BP-relative local storage")
                if not isinstance(native_stack_evidence, str):
                    raise TypeError(f"{description}['native_stack_evidence'] must be a string")
                if (
                    not native_stack_evidence
                    or native_stack_evidence.strip() != native_stack_evidence
                    or "\n" in native_stack_evidence
                    or "\r" in native_stack_evidence
                ):
                    raise ValueError(
                        f"{description}['native_stack_evidence'] must be a non-empty single-line identifier"
                    )

            normalized.append(
                (
                    callsite,
                    argument_index,
                    helper,
                    span,
                    address_kind,
                    selector_register,
                    selector_offset,
                    selector_size,
                    contract,
                    native_stack_offset,
                    native_stack_evidence,
                )
            )

    return tuple(
        sorted(
            normalized,
            key=lambda row: (
                row[0],
                row[1],
                row[2],
                row[3],
                row[8],
                row[9] is None,
                row[9] or 0,
                row[10] or "",
            ),
        )
    )


def converted_pointer_binding_map(bindings: ConvertedPointerBindings) -> ConvertedPointerBindingMap:
    """Index normalized bindings by exact callsite and argument index."""

    result: ConvertedPointerBindingMap = {}
    for (
        callsite,
        argument_index,
        helper,
        span,
        address_kind,
        selector_register,
        selector_offset,
        selector_size,
        contract,
        native_stack_offset,
        native_stack_evidence,
    ) in bindings:
        result.setdefault(callsite, {})[argument_index] = (
            helper,
            span,
            address_kind,
            selector_register,
            selector_offset,
            selector_size,
            contract,
            native_stack_offset,
            native_stack_evidence,
        )
    return result


__all__ = (
    "ConvertedPointerBinding",
    "ConvertedPointerBindingMap",
    "ConvertedPointerBindings",
    "ConvertedPointerSelector",
    "converted_pointer_binding_map",
    "normalize_converted_pointer_bindings",
)

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from archinfo import Arch

from .far_calls import _MAX_UINT64, _X86_PROTECTED_16_16, _normalize_register_range, _validate_c_identifier

type IndirectNearCallBinding = tuple[int, str, str, int, int, int, int, int]
type IndirectNearCallBindings = tuple[IndirectNearCallBinding, ...]
type IndirectNearCallBindingMap = dict[int, tuple[str, str, int, int, int, int, int]]


INDIRECT_NEAR_CALL_TARGET_REGISTERS = frozenset({"ax", "bx", "cx", "dx", "si", "di"})


_REQUIRED_KEYS = frozenset(
    {
        "dispatcher",
        "address_kind",
        "target_selector_register",
        "target_offset_register",
        "site_identifier",
    }
)


def normalize_indirect_near_call_bindings(
    arch: Arch, bindings: Mapping[int, Mapping[str, Any]] | None
) -> IndirectNearCallBindings:
    """Validate exact dynamic 16:16 near-call dispatcher bindings.

    A binding authorizes one instruction address whose original target is the
    exact segmented expression ``CS:<target register>``. It does not authorize
    other callsites or target forms. The site identifier is deliberately
    independent from the instruction address so callers can use a sealed,
    stable runtime registry key.
    """

    if bindings is None:
        return ()
    if not isinstance(bindings, Mapping):
        raise TypeError("indirect_near_call_bindings must be a mapping")

    normalized: list[IndirectNearCallBinding] = []
    for callsite, row in bindings.items():
        if not isinstance(callsite, int) or isinstance(callsite, bool):
            raise TypeError("indirect_near_call_bindings callsites must be integers")
        if callsite < 0 or callsite > _MAX_UINT64:
            raise ValueError("indirect_near_call_bindings callsites must fit in an unsigned 64-bit integer")
        if not isinstance(row, Mapping):
            raise TypeError(f"indirect_near_call_bindings[{callsite:#x}] must be a mapping")

        unknown_keys = set(row) - _REQUIRED_KEYS
        if unknown_keys:
            raise ValueError(f"Unknown indirect_near_call_bindings[{callsite:#x}] keys: {sorted(unknown_keys)!r}")
        missing_keys = _REQUIRED_KEYS - set(row)
        if missing_keys:
            raise ValueError(f"Missing indirect_near_call_bindings[{callsite:#x}] keys: {sorted(missing_keys)!r}")

        dispatcher = _validate_c_identifier(
            row["dispatcher"], f"indirect_near_call_bindings[{callsite:#x}]['dispatcher']"
        )
        address_kind = row["address_kind"]
        if not isinstance(address_kind, str):
            raise TypeError(f"indirect_near_call_bindings[{callsite:#x}]['address_kind'] must be a string")
        if address_kind != _X86_PROTECTED_16_16:
            raise ValueError(
                f"indirect_near_call_bindings[{callsite:#x}]['address_kind'] must be {_X86_PROTECTED_16_16!r}"
            )

        selector_name = row["target_selector_register"]
        if not isinstance(selector_name, str):
            raise TypeError(
                f"indirect_near_call_bindings[{callsite:#x}]['target_selector_register'] must be a register-name string"
            )
        if selector_name != "cs":
            raise ValueError(f"indirect_near_call_bindings[{callsite:#x}]['target_selector_register'] must be 'cs'")
        selector_offset, selector_size = _normalize_register_range(
            arch,
            selector_name,
            f"indirect_near_call_bindings[{callsite:#x}]['target_selector_register']",
        )
        if selector_size != 2:
            raise ValueError(
                f"indirect_near_call_bindings[{callsite:#x}]['target_selector_register'] must be 16 bits wide"
            )

        target_name = row["target_offset_register"]
        target_offset, target_size = _normalize_register_range(
            arch,
            target_name,
            f"indirect_near_call_bindings[{callsite:#x}]['target_offset_register']",
        )
        if target_name not in INDIRECT_NEAR_CALL_TARGET_REGISTERS:
            raise ValueError(
                f"indirect_near_call_bindings[{callsite:#x}]['target_offset_register'] must be one of "
                f"{sorted(INDIRECT_NEAR_CALL_TARGET_REGISTERS)!r}; stack, frame, segment, and instruction-pointer "
                "registers are not safe dynamic near-call carriers"
            )
        if target_size != 2:
            raise ValueError(
                f"indirect_near_call_bindings[{callsite:#x}]['target_offset_register'] must be 16 bits wide"
            )
        if target_offset < selector_offset + selector_size and selector_offset < target_offset + target_size:
            raise ValueError(
                f"indirect_near_call_bindings[{callsite:#x}] selector and target registers must not overlap"
            )

        site_identifier = row["site_identifier"]
        if not isinstance(site_identifier, int) or isinstance(site_identifier, bool):
            raise TypeError(f"indirect_near_call_bindings[{callsite:#x}]['site_identifier'] must be an integer")
        if site_identifier < 0 or site_identifier > 0xFFFF_FFFF:
            raise ValueError(
                f"indirect_near_call_bindings[{callsite:#x}]['site_identifier'] must fit in an unsigned 32-bit integer"
            )

        normalized.append(
            (
                callsite,
                dispatcher,
                address_kind,
                selector_offset,
                selector_size,
                target_offset,
                target_size,
                site_identifier,
            )
        )

    return tuple(sorted(normalized, key=lambda binding: binding[0]))


def indirect_near_call_binding_map(bindings: IndirectNearCallBindings) -> IndirectNearCallBindingMap:
    """Index normalized dynamic near-call bindings by exact instruction address."""

    return {
        callsite: (
            dispatcher,
            address_kind,
            selector_offset,
            selector_size,
            target_offset,
            target_size,
            site_identifier,
        )
        for (
            callsite,
            dispatcher,
            address_kind,
            selector_offset,
            selector_size,
            target_offset,
            target_size,
            site_identifier,
        ) in bindings
    }

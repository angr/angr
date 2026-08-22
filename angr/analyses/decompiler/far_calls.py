from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from archinfo import Arch

type FarCallBindingKind = Literal["internal", "external"]
type FarCallBinding = tuple[int, FarCallBindingKind, str, str | None, str | None]
type FarCallBindings = tuple[FarCallBinding, ...]
type FarCallBindingMap = dict[int, tuple[FarCallBindingKind, str, str | None, str | None]]
type RegisterRange = tuple[int, int]
type IndirectFarCallSlotOffset = tuple[Literal["constant", "register"], int, int]
type IndirectFarCallBinding = tuple[
    int,
    str,
    str,
    int,
    int,
    IndirectFarCallSlotOffset,
    int | None,
    tuple[RegisterRange, ...],
]
type IndirectFarCallBindings = tuple[IndirectFarCallBinding, ...]
type IndirectFarCallBindingMap = dict[
    int,
    tuple[str, str, int, int, IndirectFarCallSlotOffset, int | None, tuple[RegisterRange, ...]],
]


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
_VALID_KEYS = frozenset({"begin", "end", "internal_targets", "external_targets"})
_INDIRECT_COMMON_KEYS = frozenset(
    {
        "dispatcher",
        "address_kind",
        "slot_selector_register",
        "register_inputs",
    }
)
_INDIRECT_SLOT_OFFSET_KEYS = frozenset({"slot_offset", "slot_offset_register"})
_INDIRECT_OPTIONAL_KEYS = frozenset({"site_identifier"})
_X86_PROTECTED_16_16 = "x86-protected-16:16"
_MAX_UINT64 = (1 << 64) - 1


def _validate_c_identifier(value: Any, description: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{description} must be a string")
    if _C_IDENTIFIER_RE.fullmatch(value) is None or value in _C_KEYWORDS:
        raise ValueError(f"{description} must be a valid non-keyword C identifier: {value!r}")
    return value


def _normalize_target_map(value: Any, description: str) -> dict[int, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"far_call_bindings[{description!r}] must be a mapping")

    normalized: dict[int, str] = {}
    for target_addr, target_symbol in value.items():
        if not isinstance(target_addr, int) or isinstance(target_addr, bool):
            raise TypeError(f"far_call_bindings[{description!r}] addresses must be integers")
        if target_addr < 0 or target_addr > _MAX_UINT64:
            raise ValueError(f"far_call_bindings[{description!r}] addresses must fit in an unsigned 64-bit integer")
        normalized[target_addr] = _validate_c_identifier(
            target_symbol, f"far_call_bindings[{description!r}][{target_addr:#x}]"
        )
    return normalized


def normalize_far_call_bindings(bindings: Mapping[str, Any] | None) -> FarCallBindings:
    """Validate and deterministically normalize direct far-call bindings.

    The input is an exact allowlist. ``internal_targets`` maps direct target
    addresses to embedding-runtime logical segment identifiers. Each internal
    call is emitted between ``begin(segment_identifier)`` and ``end()`` calls.
    The helpers, rather than generated C, own selector resolution, nesting, and
    restoration of the caller's runtime CS.

    ``external_targets`` maps direct target addresses to exact host wrapper
    names. External wrappers are called directly and deliberately receive no
    synthetic CS transition. Indirect, segmented-expression, unknown, and
    unmapped far calls remain unsupported.
    """

    if bindings is None:
        return ()
    if not isinstance(bindings, Mapping):
        raise TypeError("far_call_bindings must be a mapping")

    unknown_keys = set(bindings) - _VALID_KEYS
    if unknown_keys:
        raise ValueError(f"Unknown far_call_bindings keys: {sorted(unknown_keys)!r}")

    begin = bindings.get("begin")
    end = bindings.get("end")
    if (begin is None) != (end is None):
        raise ValueError("far_call_bindings begin and end helpers must be supplied together")
    if begin is not None:
        begin = _validate_c_identifier(begin, "far_call_bindings['begin']")
        end = _validate_c_identifier(end, "far_call_bindings['end']")

    internal_targets = _normalize_target_map(bindings.get("internal_targets"), "internal_targets")
    external_targets = _normalize_target_map(bindings.get("external_targets"), "external_targets")
    duplicate_targets = set(internal_targets) & set(external_targets)
    if duplicate_targets:
        rendered = ", ".join(f"{addr:#x}" for addr in sorted(duplicate_targets))
        raise ValueError(f"Far-call target addresses cannot be both internal and external: {rendered}")
    if internal_targets and begin is None:
        raise ValueError("Internal far-call targets require begin and end helpers")

    normalized: list[FarCallBinding] = [
        (target_addr, "internal", target_symbol, begin, end) for target_addr, target_symbol in internal_targets.items()
    ]
    normalized.extend(
        (target_addr, "external", target_symbol, None, None) for target_addr, target_symbol in external_targets.items()
    )
    return tuple(sorted(normalized, key=lambda binding: (binding[0], binding[1])))


def far_call_binding_map(bindings: FarCallBindings) -> FarCallBindingMap:
    """Index normalized bindings by exact direct target address."""

    return {
        target_addr: (kind, target_symbol, begin_helper, end_helper)
        for target_addr, kind, target_symbol, begin_helper, end_helper in bindings
    }


def _normalize_register_range(arch: Arch, register_name: Any, description: str) -> RegisterRange:
    if not isinstance(register_name, str):
        raise TypeError(f"{description} must be a register-name string")
    if register_name not in arch.registers:
        raise KeyError(f"Unknown register in {description}: {register_name!r}")
    offset, size = arch.registers[register_name]
    if size <= 0:
        raise ValueError(f"{description} must name a nonempty architectural register")
    return offset, size


def normalize_indirect_far_call_bindings(
    arch: Arch, bindings: Mapping[int, Mapping[str, Any]] | None
) -> IndirectFarCallBindings:
    """Validate exact dynamic 16:16 far-call dispatcher bindings.

    Each row authorizes one instruction address, not a target value. The slot
    selector and offset source describe the memory operand whose two words
    supply the runtime offset and selector. Exactly one of ``slot_offset`` or
    ``slot_offset_register`` is required. ``register_inputs`` is an
    ABI-significant ordered list of current machine-register values passed
    after the selector and slot offset. Aliasing inputs are rejected because
    their order would not define independent values.
    """

    if bindings is None:
        return ()
    if not isinstance(bindings, Mapping):
        raise TypeError("indirect_far_call_bindings must be a mapping")

    normalized: list[IndirectFarCallBinding] = []
    for callsite, row in bindings.items():
        if not isinstance(callsite, int) or isinstance(callsite, bool):
            raise TypeError("indirect_far_call_bindings callsites must be integers")
        if callsite < 0 or callsite > _MAX_UINT64:
            raise ValueError("indirect_far_call_bindings callsites must fit in an unsigned 64-bit integer")
        if not isinstance(row, Mapping):
            raise TypeError(f"indirect_far_call_bindings[{callsite:#x}] must be a mapping")

        unknown_keys = set(row) - (_INDIRECT_COMMON_KEYS | _INDIRECT_SLOT_OFFSET_KEYS | _INDIRECT_OPTIONAL_KEYS)
        if unknown_keys:
            raise ValueError(f"Unknown indirect_far_call_bindings[{callsite:#x}] keys: {sorted(unknown_keys)!r}")
        missing_keys = _INDIRECT_COMMON_KEYS - set(row)
        if missing_keys:
            raise ValueError(f"Missing indirect_far_call_bindings[{callsite:#x}] keys: {sorted(missing_keys)!r}")
        offset_keys = set(row) & _INDIRECT_SLOT_OFFSET_KEYS
        if len(offset_keys) != 1:
            raise ValueError(
                f"indirect_far_call_bindings[{callsite:#x}] must contain exactly one of "
                "'slot_offset' or 'slot_offset_register'"
            )

        dispatcher = _validate_c_identifier(
            row["dispatcher"], f"indirect_far_call_bindings[{callsite:#x}]['dispatcher']"
        )
        address_kind = row["address_kind"]
        if not isinstance(address_kind, str):
            raise TypeError(f"indirect_far_call_bindings[{callsite:#x}]['address_kind'] must be a string")
        if address_kind != _X86_PROTECTED_16_16:
            raise ValueError(
                f"indirect_far_call_bindings[{callsite:#x}]['address_kind'] must be {_X86_PROTECTED_16_16!r}"
            )

        selector_name = row["slot_selector_register"]
        if not isinstance(selector_name, str):
            raise TypeError(
                f"indirect_far_call_bindings[{callsite:#x}]['slot_selector_register'] must be a register-name string"
            )
        if selector_name not in {"ds", "ss"}:
            raise ValueError(
                f"indirect_far_call_bindings[{callsite:#x}]['slot_selector_register'] must be 'ds' or 'ss'"
            )
        selector_offset, selector_size = _normalize_register_range(
            arch,
            selector_name,
            f"indirect_far_call_bindings[{callsite:#x}]['slot_selector_register']",
        )
        if selector_size != 2:
            raise ValueError(
                f"indirect_far_call_bindings[{callsite:#x}]['slot_selector_register'] must be 16 bits wide"
            )

        if "slot_offset" in offset_keys:
            slot_offset = row["slot_offset"]
            if not isinstance(slot_offset, int) or isinstance(slot_offset, bool):
                raise TypeError(f"indirect_far_call_bindings[{callsite:#x}]['slot_offset'] must be an integer")
            if slot_offset < 0 or slot_offset > 0xFFFF:
                raise ValueError(
                    f"indirect_far_call_bindings[{callsite:#x}]['slot_offset'] must fit in an unsigned 16-bit integer"
                )
            slot_offset_source: IndirectFarCallSlotOffset = ("constant", slot_offset, 2)
        else:
            slot_offset_register = _normalize_register_range(
                arch,
                row["slot_offset_register"],
                f"indirect_far_call_bindings[{callsite:#x}]['slot_offset_register']",
            )
            if slot_offset_register[1] != 2:
                raise ValueError(
                    f"indirect_far_call_bindings[{callsite:#x}]['slot_offset_register'] must be 16 bits wide"
                )
            slot_offset_source = ("register", *slot_offset_register)

        site_identifier = row.get("site_identifier")
        if "site_identifier" in row:
            if not isinstance(site_identifier, int) or isinstance(site_identifier, bool):
                raise TypeError(f"indirect_far_call_bindings[{callsite:#x}]['site_identifier'] must be an integer")
            if site_identifier < 0 or site_identifier > 0xFFFF_FFFF:
                raise ValueError(
                    f"indirect_far_call_bindings[{callsite:#x}]['site_identifier'] must fit in an unsigned "
                    "32-bit integer"
                )

        input_names = row["register_inputs"]
        if not isinstance(input_names, Sequence) or isinstance(input_names, (str, bytes, bytearray)):
            raise TypeError(
                f"indirect_far_call_bindings[{callsite:#x}]['register_inputs'] must be an ordered register sequence"
            )
        input_ranges: list[RegisterRange] = []
        for input_index, register_name in enumerate(input_names):
            register_range = _normalize_register_range(
                arch,
                register_name,
                f"indirect_far_call_bindings[{callsite:#x}]['register_inputs'][{input_index}]",
            )
            if register_range[1] not in {1, 2, 4, 8}:
                raise ValueError(
                    f"indirect_far_call_bindings[{callsite:#x}]['register_inputs'][{input_index}] must name an "
                    "unsigned scalar register of 8, 16, 32, or 64 bits"
                )
            for existing_offset, existing_size in input_ranges:
                register_offset, register_size = register_range
                if (
                    register_offset < existing_offset + existing_size
                    and existing_offset < register_offset + register_size
                ):
                    raise ValueError(f"indirect_far_call_bindings[{callsite:#x}]['register_inputs'] must not overlap")
            input_ranges.append(register_range)

        normalized.append(
            (
                callsite,
                dispatcher,
                address_kind,
                selector_offset,
                selector_size,
                slot_offset_source,
                site_identifier,
                tuple(input_ranges),
            )
        )

    return tuple(sorted(normalized, key=lambda binding: binding[0]))


def indirect_far_call_binding_map(bindings: IndirectFarCallBindings) -> IndirectFarCallBindingMap:
    """Index normalized dynamic far-call bindings by exact instruction address."""

    return {
        callsite: (
            dispatcher,
            address_kind,
            selector_offset,
            selector_size,
            slot_offset_source,
            site_identifier,
            input_ranges,
        )
        for (
            callsite,
            dispatcher,
            address_kind,
            selector_offset,
            selector_size,
            slot_offset_source,
            site_identifier,
            input_ranges,
        ) in bindings
    }

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Literal

import archinfo

type RegisterStateBinding = tuple[int, int, str]
type RegisterStateBindings = tuple[RegisterStateBinding, ...]
type RegisterStateBindingKey = str | tuple[int, int]
type InitialRegisterStateBinding = tuple[int, int, str]
type InitialRegisterStateBindings = tuple[InitialRegisterStateBinding, ...]
type PostCallRegisterStateSelectorKind = Literal["callee_name", "callee_addr", "callsite_addr"]
type PostCallRegisterStateSelector = tuple[PostCallRegisterStateSelectorKind, str | int]
type PostCallRegisterStateBinding = tuple[PostCallRegisterStateSelectorKind, str | int, int, int, str]
type PostCallRegisterStateBindings = tuple[PostCallRegisterStateBinding, ...]

_C_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def normalize_register_state_bindings(
    arch: archinfo.Arch,
    bindings: Mapping[RegisterStateBindingKey, str] | None,
) -> RegisterStateBindings:
    """Normalize external architectural-register state bindings.

    Register names are resolved through ``arch.registers``. Tuple keys are
    ``(register_offset, size_in_bytes)`` and allow callers to bind registers
    that do not have a stable architecture-independent name. Binding values
    are C lvalue expressions supplied by the embedding runtime and are emitted
    verbatim by C code generation.
    """

    if bindings is None:
        return ()
    if not isinstance(bindings, Mapping):
        raise TypeError("register_state_bindings must be a mapping")

    normalized: dict[tuple[int, int], str] = {}
    for key, lvalue in bindings.items():
        if isinstance(key, str):
            register = arch.registers.get(key)
            if register is None:
                register = arch.registers.get(key.lower())
            if register is None:
                raise KeyError(f"Unknown register in register_state_bindings: {key!r}")
            register_offset, size = register
        elif isinstance(key, tuple) and len(key) == 2 and isinstance(key[0], int) and isinstance(key[1], int):
            register_offset, size = key
        else:
            raise TypeError("register_state_bindings keys must be register names or (offset, size) tuples")

        if register_offset < 0:
            raise ValueError("register_state_bindings offsets must be non-negative")
        if size <= 0:
            raise ValueError("register_state_bindings sizes must be positive")
        if not isinstance(lvalue, str):
            raise TypeError("register_state_bindings values must be C lvalue strings")
        if not lvalue or lvalue.strip() != lvalue or "\n" in lvalue or "\r" in lvalue:
            raise ValueError("register_state_bindings values must be non-empty single-line C lvalues")

        storage = register_offset, size
        if storage in normalized and normalized[storage] != lvalue:
            raise ValueError(f"Conflicting register_state_bindings for register storage {storage!r}")
        normalized[storage] = lvalue

    ordered = tuple((offset, size, lvalue) for (offset, size), lvalue in sorted(normalized.items()))
    for previous, current in zip(ordered, ordered[1:]):
        previous_offset, previous_size, _ = previous
        current_offset, _, _ = current
        if current_offset < previous_offset + previous_size:
            raise ValueError(
                "register_state_bindings ranges must not overlap: "
                f"{previous_offset, previous_size!r} and {current_offset, current[1]!r}"
            )
    return ordered


def normalize_initial_register_state_bindings(
    arch: archinfo.Arch,
    bindings: Mapping[RegisterStateBindingKey, str] | None,
) -> InitialRegisterStateBindings:
    """Normalize immutable C identifiers that provide machine-register values at function entry.

    Unlike :func:`normalize_register_state_bindings`, these expressions are not mutable register storage. They are
    substituted only for reads reached by the function-entry external definition; later machine definitions remain
    ordinary SSA locals. Binding identifiers must therefore expand to stable, side-effect-free values for the duration of the
    recovered function.
    """

    if bindings is None:
        return ()
    if not isinstance(bindings, Mapping):
        raise TypeError("initial_register_state_bindings must be a mapping")

    normalized: dict[tuple[int, int], str] = {}
    for key, expression in bindings.items():
        if isinstance(key, str):
            register = arch.registers.get(key)
            if register is None:
                register = arch.registers.get(key.lower())
            if register is None:
                raise KeyError(f"Unknown register in initial_register_state_bindings: {key!r}")
            register_offset, size = register
        elif isinstance(key, tuple) and len(key) == 2 and isinstance(key[0], int) and isinstance(key[1], int):
            register_offset, size = key
        else:
            raise TypeError("initial_register_state_bindings keys must be register names or (offset, size) tuples")

        if register_offset < 0:
            raise ValueError("initial_register_state_bindings offsets must be non-negative")
        if size <= 0:
            raise ValueError("initial_register_state_bindings sizes must be positive")
        if not isinstance(expression, str):
            raise TypeError("initial_register_state_bindings values must be C identifier strings")
        if _C_IDENTIFIER_RE.fullmatch(expression) is None:
            raise ValueError("initial_register_state_bindings values must be C identifiers")

        storage = register_offset, size
        if storage in normalized and normalized[storage] != expression:
            raise ValueError(f"Conflicting initial_register_state_bindings for register storage {storage!r}")
        normalized[storage] = expression

    ordered = tuple((offset, size, expression) for (offset, size), expression in sorted(normalized.items()))
    for previous, current in zip(ordered, ordered[1:]):
        previous_offset, previous_size, _ = previous
        current_offset, _, _ = current
        if current_offset < previous_offset + previous_size:
            raise ValueError(
                "initial_register_state_bindings ranges must not overlap: "
                f"{previous_offset, previous_size!r} and {current_offset, current[1]!r}"
            )
    return ordered


def normalize_post_call_register_state_bindings(
    arch: archinfo.Arch,
    bindings: Mapping[PostCallRegisterStateSelector, Mapping[RegisterStateBindingKey, str]] | None,
) -> PostCallRegisterStateBindings:
    """Normalize immutable register values produced by selected calls.

    Selectors are explicit ``(kind, value)`` tuples. ``callee_name`` matches the exact canonical name of a resolved
    callee (or an unresolved literal string target), ``callee_addr`` matches an exact direct-call target address, and
    ``callsite_addr`` matches the call instruction address. Binding values are C identifiers, which may name
    object-like macros. They must expand to stable, side-effect-free values until the corresponding machine register
    is redefined.

    Name and address matching deliberately do not guess through indirect calls. An indirect call can only receive
    effects through an explicit ``callsite_addr`` selector.
    """

    if bindings is None:
        return ()
    if not isinstance(bindings, Mapping):
        raise TypeError("post_call_register_state_bindings must be a mapping")

    normalized = []
    for selector, register_bindings in bindings.items():
        if not isinstance(selector, tuple) or len(selector) != 2:
            raise TypeError("post_call_register_state_bindings keys must be (selector_kind, selector_value) tuples")
        selector_kind, selector_value = selector
        if selector_kind not in {"callee_name", "callee_addr", "callsite_addr"}:
            raise ValueError(f"Unknown post-call register-state selector kind: {selector_kind!r}")
        if selector_kind == "callee_name":
            if not isinstance(selector_value, str):
                raise TypeError("callee_name selector values must be strings")
            if (
                not selector_value
                or selector_value.strip() != selector_value
                or "\n" in selector_value
                or "\r" in selector_value
            ):
                raise ValueError("callee_name selector values must be non-empty single-line names")
        elif not isinstance(selector_value, int) or isinstance(selector_value, bool):
            raise TypeError(f"{selector_kind} selector values must be integers")
        elif selector_value < 0:
            raise ValueError(f"{selector_kind} selector values must be non-negative")

        if not isinstance(register_bindings, Mapping):
            raise TypeError(f"post_call_register_state_bindings[{selector!r}] must be a mapping")
        if not register_bindings:
            raise ValueError(f"post_call_register_state_bindings[{selector!r}] must not be empty")
        register_rows = normalize_initial_register_state_bindings(arch, register_bindings)
        normalized.extend(
            (selector_kind, selector_value, register_offset, size, expression)
            for register_offset, size, expression in register_rows
        )

    return tuple(
        sorted(
            normalized,
            key=lambda row: (
                {"callee_name": 0, "callee_addr": 1, "callsite_addr": 2}[row[0]],
                row[1],
                row[2],
                row[3],
                row[4],
            ),
        )
    )


def post_call_register_state_bindings_for_call(
    bindings: PostCallRegisterStateBindings,
    *,
    callee_name: str | None,
    callee_addr: int | None,
    callsite_addr: int | None,
) -> InitialRegisterStateBindings:
    """Return the bindings selected for one resolved call identity.

    Multiple selectors may intentionally contribute disjoint register ranges. If two matching selectors cover any
    of the same register storage, resolution fails instead of choosing an implicit precedence rule.
    """

    matches = []
    for selector_kind, selector_value, register_offset, size, expression in bindings:
        selected = (
            (selector_kind == "callee_name" and selector_value == callee_name)
            or (selector_kind == "callee_addr" and selector_value == callee_addr)
            or (selector_kind == "callsite_addr" and selector_value == callsite_addr)
        )
        if selected:
            matches.append((register_offset, size, expression, selector_kind, selector_value))

    matches.sort(key=lambda row: (row[0], row[1], row[2], row[3], str(row[4])))
    for previous, current in zip(matches, matches[1:]):
        previous_offset, previous_size, _, previous_kind, previous_value = previous
        current_offset, current_size, _, current_kind, current_value = current
        if current_offset < previous_offset + previous_size:
            raise ValueError(
                "Matching post_call_register_state_bindings ranges must not overlap: "
                f"{(previous_kind, previous_value)!r} binds {(previous_offset, previous_size)!r} and "
                f"{(current_kind, current_value)!r} binds {(current_offset, current_size)!r}"
            )
    return tuple((offset, size, expression) for offset, size, expression, _, _ in matches)


def register_state_binding_map(bindings: RegisterStateBindings) -> dict[tuple[int, int], str]:
    return {(offset, size): lvalue for offset, size, lvalue in bindings}


def register_state_ranges(bindings: RegisterStateBindings) -> tuple[tuple[int, int], ...]:
    return tuple((offset, size) for offset, size, _ in bindings)


def initial_register_state_binding_map(
    bindings: InitialRegisterStateBindings,
) -> dict[tuple[int, int], str]:
    return {(offset, size): expression for offset, size, expression in bindings}


def initial_register_state_ranges(bindings: InitialRegisterStateBindings) -> tuple[tuple[int, int], ...]:
    return tuple((offset, size) for offset, size, _ in bindings)


__all__ = (
    "InitialRegisterStateBinding",
    "InitialRegisterStateBindings",
    "PostCallRegisterStateBinding",
    "PostCallRegisterStateBindings",
    "PostCallRegisterStateSelector",
    "PostCallRegisterStateSelectorKind",
    "RegisterStateBinding",
    "RegisterStateBindingKey",
    "RegisterStateBindings",
    "initial_register_state_binding_map",
    "initial_register_state_ranges",
    "normalize_initial_register_state_bindings",
    "normalize_post_call_register_state_bindings",
    "normalize_register_state_bindings",
    "post_call_register_state_bindings_for_call",
    "register_state_binding_map",
    "register_state_ranges",
)

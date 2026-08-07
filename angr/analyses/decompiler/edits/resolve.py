"""
Resolution helpers shared by every edit operation: address-or-name to Function, and pseudocode
display name to the underlying SimVariable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from angr.sim_variable import SimMemoryVariable, SimStackVariable

from .cache import DEFAULT_FLAVOR, require_cache
from .errors import (
    AmbiguousFunctionError,
    FunctionNotFoundError,
    InvalidNameError,
    VariableNotFoundError,
)

if TYPE_CHECKING:
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.sim_variable import SimVariable

_C_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

VariableKind = Literal["argument", "local", "global"]


def parse_address(value: str | int) -> int:
    """Parse an address given as an int or a string. Accepts 0x-prefixed hex and decimal."""
    if isinstance(value, int):
        return value
    try:
        return int(value, 0)
    except (TypeError, ValueError) as ex:
        raise InvalidNameError(f'Invalid address {value!r}. Pass a hex string such as "0x401000".') from ex


def validate_name(name: str, *, strict: bool = True) -> None:
    """
    Reject names that cannot be used as identifiers.

    ``strict`` requires a C identifier. Without it only whitespace-free names are required, which
    still admits things like ``int;`` that render as uncompilable C -- so strict is the default.
    """
    if not name:
        raise InvalidNameError("Name must not be empty.")
    if strict:
        if _C_IDENTIFIER_RE.match(name) is None:
            raise InvalidNameError(
                f"Invalid name {name!r}: must be a C identifier (letters, digits and underscores, "
                "not starting with a digit)."
            )
    elif re.search(r"\s", name) is not None:
        raise InvalidNameError(f"Invalid name {name!r}: names must not contain whitespace.")


def resolve_function(
    kb: KnowledgeBase,
    *,
    address: str | int | None = None,
    name: str | None = None,
    containing: bool = True,
) -> Function:
    """
    Find a function by address or by name.

    :param containing:  If True, an address inside a function resolves to that function rather
                        than requiring the exact entry address.
    """
    if address is None and name is None:
        raise FunctionNotFoundError("Specify either an address or a name.")

    if address is not None:
        addr = parse_address(address)
        func = kb.functions.get(addr)
        if func is None and containing:
            func = kb.functions.floor_func(addr)
            if func is not None and not (func.addr <= addr < func.addr + max(func.size, 1)):
                func = None
        if func is None:
            raise FunctionNotFoundError(f"No function found at address {addr:#x}.")
        return func

    matches = [f for f in kb.functions.get_by_name(name) if f is not None]
    if not matches:
        raise FunctionNotFoundError(f"No function named {name!r}.")
    if len(matches) > 1:
        addrs = sorted(f.addr for f in matches)
        raise AmbiguousFunctionError(
            f"{len(matches)} functions are named {name!r}: {', '.join(hex(a) for a in addrs)}. "
            "Specify an address instead.",
            addresses=addrs,
        )
    return matches[0]


@dataclass(frozen=True)
class ResolvedVariable:
    """
    A pseudocode display name resolved to the objects an edit needs.

    ``variable`` is the concrete/SSA variable that ``set_variable_type`` expects; ``unified`` is the
    unified variable that a rename mutates (None for globals, which have no unified form).
    """

    kind: VariableKind
    variable: SimVariable
    unified: SimVariable | None
    cvar: CVariable | None = None
    arg_index: int | None = None
    stack_offset: int | None = None
    global_addr: int | None = None
    ambiguous: bool = False

    @property
    def name(self) -> str | None:
        target = self.variable if self.unified is None else self.unified
        return target.name

    @property
    def storage(self) -> str:
        if self.stack_offset is not None:
            return "stack"
        if isinstance(self.variable, SimMemoryVariable) and not isinstance(self.variable, SimStackVariable):
            return "memory"
        return "register"

    def detail(self) -> dict:
        return {
            "storage": self.storage,
            "is_argument": self.kind == "argument",
            "stack_offset": self.stack_offset,
            "arg_index": self.arg_index,
            "global_address": None if self.global_addr is None else hex(self.global_addr),
        }


def _stack_offset(var: SimVariable) -> int | None:
    return var.offset if isinstance(var, SimStackVariable) else None


def _iter_candidates(kb: KnowledgeBase, func_addr: int, codegen) -> list[ResolvedVariable]:
    """
    Collect every addressable variable, in precedence order: arguments, then locals, then globals.

    Locals come from the codegen (which carries the concrete variable) unioned with the variable
    manager's unified variables, so unified variables not currently referenced in the body are still
    addressable. Globals come from cexterns first, then any non-stack memory variable in use, then a
    walk of the position map for inline references that cexterns filters out.
    """
    out: list[ResolvedVariable] = []
    seen: set[int] = set()

    cfunc = getattr(codegen, "cfunc", None)

    if cfunc is not None and cfunc.arg_list:
        for idx, cvar in enumerate(cfunc.arg_list):
            var = getattr(cvar, "variable", None)
            if var is None:
                continue
            unified = getattr(cvar, "unified_variable", None) or var
            out.append(
                ResolvedVariable(
                    kind="argument",
                    variable=var,
                    unified=unified,
                    cvar=cvar,
                    arg_index=idx,
                    stack_offset=_stack_offset(var),
                )
            )
            seen.add(id(unified))

    if cfunc is not None and cfunc.variables_in_use:
        for var, cvar in cfunc.variables_in_use.items():
            unified = getattr(cvar, "unified_variable", None)
            if unified is None or id(unified) in seen:
                continue
            out.append(
                ResolvedVariable(
                    kind="local",
                    variable=var,
                    unified=unified,
                    cvar=cvar,
                    stack_offset=_stack_offset(var),
                )
            )
            seen.add(id(unified))

    if kb.dec_variables.has_function_manager(func_addr):
        varman = kb.dec_variables[func_addr]
        concrete_by_unified: dict[int, SimVariable] = {}
        for var in varman.get_variables(sort=None):
            unified = varman.unified_variable(var)
            if unified is not None:
                concrete_by_unified.setdefault(id(unified), var)
        for unified in varman.get_unified_variables(sort=None):
            if id(unified) in seen:
                continue
            # prefer a concrete SSA variable: set_variable_type(all_unified=True) keys off the
            # SSA-to-unified map, so passing the unified variable would not propagate
            concrete = concrete_by_unified.get(id(unified), unified)
            out.append(
                ResolvedVariable(
                    kind="local",
                    variable=concrete,
                    unified=unified,
                    stack_offset=_stack_offset(concrete),
                )
            )
            seen.add(id(unified))

    for cvar in _iter_global_cvars(codegen, cfunc):
        var = cvar.variable
        if var is None or id(var) in seen:
            continue
        out.append(
            ResolvedVariable(
                kind="global",
                variable=var,
                unified=None,
                cvar=cvar,
                global_addr=getattr(var, "addr", None),
            )
        )
        seen.add(id(var))

    return out


def concrete_variables(varman, resolved: ResolvedVariable) -> list[SimVariable]:
    """
    Every SSA variable sharing the resolved variable's unified form.

    Retyping applies to all of them. Computed here rather than relying on
    ``set_variable_type(all_unified=True)``, which silently does nothing when the variable it is
    handed is not a key in the SSA-to-unified map.
    """
    if resolved.unified is None:
        return [resolved.variable]

    out = [var for var in varman.get_variables(sort=None) if varman.unified_variable(var) is resolved.unified]
    if not any(var is resolved.variable for var in out):
        out.append(resolved.variable)
    return out


def _iter_global_cvars(codegen, cfunc):
    from angr.analyses.decompiler.structured_codegen.c import CVariable  # pylint:disable=import-outside-toplevel

    if codegen.cexterns:
        yield from codegen.cexterns

    if cfunc is not None and cfunc.variables_in_use:
        for var, cvar in cfunc.variables_in_use.items():
            if (
                getattr(cvar, "unified_variable", None) is None
                and isinstance(var, SimMemoryVariable)
                and not isinstance(var, SimStackVariable)
            ):
                yield cvar

    # inline references (strings, function pointers) that cexterns filters out
    if codegen.map_pos_to_node is not None:
        for item in codegen.map_pos_to_node.values():
            obj = getattr(item, "obj", None)
            if isinstance(obj, CVariable) and obj.unified_variable is None and obj.variable is not None:
                yield obj


def list_variable_names(codegen, kb: KnowledgeBase | None = None, func_addr: int | None = None) -> list[str]:
    """Every display name addressable in this decompilation, for error messages."""
    if kb is None or func_addr is None:
        cfunc = getattr(codegen, "cfunc", None)
        names = set()
        if cfunc is not None:
            for cvar in cfunc.arg_list or []:
                if cvar.name:
                    names.add(cvar.name)
            for cvar in (cfunc.variables_in_use or {}).values():
                if cvar.name:
                    names.add(cvar.name)
        return sorted(names)

    return sorted({rv.name for rv in _iter_candidates(kb, func_addr, codegen) if rv.name})


def resolve_variable(
    kb: KnowledgeBase,
    func_addr: int,
    display_name: str,
    *,
    codegen=None,
    flavor: str = DEFAULT_FLAVOR,
) -> ResolvedVariable:
    """
    Resolve a name as it appears in the pseudocode to the underlying variable.

    Precedence is argument > local > global. A name matching more than one variable within the same
    bucket resolves deterministically and sets ``ambiguous``, rather than failing -- a batch edit
    should be able to report the collision and continue.
    """
    if codegen is None:
        codegen = require_cache(kb, func_addr, flavor).codegen

    candidates = _iter_candidates(kb, func_addr, codegen)
    matches = [rv for rv in candidates if rv.name == display_name]

    if not matches:
        raise VariableNotFoundError(
            f"No variable named {display_name!r} in the decompilation of function {func_addr:#x}.",
            candidates=sorted({rv.name for rv in candidates if rv.name}),
        )

    if len(matches) == 1:
        return matches[0]

    order = {"argument": 0, "local": 1, "global": 2}
    matches.sort(
        key=lambda rv: (
            order[rv.kind],
            rv.arg_index if rv.arg_index is not None else 0,
            rv.variable.ident or "",
            rv.global_addr if rv.global_addr is not None else 0,
        )
    )
    best = matches[0]
    return ResolvedVariable(
        kind=best.kind,
        variable=best.variable,
        unified=best.unified,
        cvar=best.cvar,
        arg_index=best.arg_index,
        stack_offset=best.stack_offset,
        global_addr=best.global_addr,
        ambiguous=True,
    )

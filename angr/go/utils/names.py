from __future__ import annotations

import re

from angr.ailment.expression import Call, Const
from angr.utils.go_runtime import normalize_go_func_name

MORESTACK_FUNCTIONS = frozenset({"runtime.morestack", "runtime.morestack_noctxt", "runtime.morestackc"})


def is_go_morestack_name(name: str | None) -> bool:
    return name is not None and normalize_go_func_name(name) in MORESTACK_FUNCTIONS


def call_target_name(project, call: Call) -> str | None:
    """
    The name of the function a call targets, or None if the target is not a known function.
    """
    target = call.target
    if isinstance(target, str):
        return target
    if isinstance(target, Const):
        addr = target.value_int
        if project.kb.functions.contains_addr(addr):
            return project.kb.functions.get_by_addr(addr).name
        sym = project.loader.find_symbol(addr)
        if sym is not None:
            return sym.name
    return None


_CLOSURE_SUFFIX = re.compile(r"\.(?:func|gowrap|deferwrap)\d+(?:\.\d+)*$|-range\d+(?:\.\d+)*$|-fm$")


def is_go_closure_name(name: str | None) -> bool:
    """``pkg.f.func1``, ``pkg.f.gowrap2``, ``pkg.T.M-fm``: bodies that receive a closure context."""
    return name is not None and _CLOSURE_SUFFIX.search(name) is not None

from __future__ import annotations

import re

from angr.ailment.expression import Call, Const
from angr.utils.go_runtime import GO_STACK_GROWTH_NAMES, normalize_go_func_name

MORESTACK_FUNCTIONS = GO_STACK_GROWTH_NAMES


def is_go_morestack_name(name: str | None) -> bool:
    return name is not None and normalize_go_func_name(name) in MORESTACK_FUNCTIONS


def is_go_morestack_call(project, call: Call) -> bool:
    """
    Whether ``call`` targets a goroutine stack-growth stub, identified by name or (in binaries without names) by
    the shape-based identification CFGFast records.
    """
    if is_go_morestack_name(call_target_name(project, call)):
        return True
    if isinstance(call.target, Const):
        return call.target.value_int in project.kb.functions.get_key_func_addrs("go_stack_growth")
    return False


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


_OPEN = {"[": "]", "(": ")", "{": "}"}


def _top_level_positions(name: str, chars: str) -> list[int] | None:
    """Positions of ``chars`` outside brackets and string literals (type arguments spell arbitrary types)."""
    out = []
    depth = 0
    quote = None
    i = 0
    while i < len(name):
        c = name[i]
        if quote is not None:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = None
        elif c in '"`':
            quote = c
        elif c in _OPEN:
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and c in chars:
            out.append(i)
        i += 1
    return out if depth == 0 and quote is None else None


def split_go_func_name(name: str) -> tuple[str, list[str]] | None:
    """
    ``pkg/path.(*T[A]).M`` -> ``("pkg/path", ["(*T[A])", "M"])``: the package path, then the dot-separated parts after
    it. Dots, commas and slashes inside type arguments (``F[go.shape.struct { a.B }]``) do not split.
    """
    slashes = _top_level_positions(name, "/")
    dots = _top_level_positions(name, ".")
    if slashes is None or dots is None:
        return None
    last_slash = slashes[-1] if slashes else -1
    dots = [d for d in dots if d > last_slash]
    if not dots:
        return None
    pkg_end = dots[0]
    parts = []
    start = pkg_end + 1
    for d in dots[1:]:
        parts.append(name[start:d])
        start = d + 1
    parts.append(name[start:])
    if not all(parts):
        return None
    return name[:pkg_end], parts


def split_go_method_name(name: str) -> tuple[str, str, bool, str] | None:
    """
    ``pkg.(*T).M`` -> ``(pkg, "T", True, "M")``, ``pkg.T[A].M`` -> ``(pkg, "T[A]", False, "M")``; None for plain
    functions and closures (``pkg.f.func1``, ``pkg.T.M-fm``).
    """
    if is_go_closure_name(name):
        return None
    split = split_go_func_name(name)
    if split is None or len(split[1]) != 2:
        return None
    pkg, (recv, method) = split
    if re.fullmatch(r"[A-Za-z_]\w*", method) is None or re.fullmatch(r"(?:func|gowrap|deferwrap)\d+", method):
        return None
    ptr = recv.startswith("(*") and recv.endswith(")")
    tname = recv[2:-1] if ptr else recv
    if not tname or tname[0] in "(*[" or (not ptr and "(" in tname.split("[", 1)[0]):
        return None
    return pkg, tname, ptr, method

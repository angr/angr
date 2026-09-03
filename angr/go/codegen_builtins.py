"""
Rendering of Go builtins and operator-like statements that the runtime rewriter encodes as AIL ``Call`` expressions.

A rewritten call has a plain-string target and may carry a ``go_render`` tag that selects one of the operator forms
below (the argument layout is fixed per kind). Calls without the tag render as ``name(args)`` by the regular call
printer, which also prints the ``go_type_args`` tag (a list of Go type strings) before the arguments, so
``Call("make", [n], go_type_args=["chan int"])`` renders as ``make(chan int, n)``.

``go_render`` kinds:

- ``"index"``: ``[m, k]`` -> ``m[k]`` (also for the tuple-valued ``v, ok = m[k]`` form; the destination is the
  assignment's left-hand side)
- ``"assign"``: ``[m, k, v]`` -> ``m[k] = v``
- ``"send"``: ``[c, v]`` -> ``c <- v``
- ``"recv"``: ``[c]`` -> ``<-c``
- ``"go"``: ``[f, args...]`` -> ``go f(args...)``
- ``"defer"``: ``[f, args...]`` -> ``defer f(args...)``
"""

from __future__ import annotations

from collections.abc import Iterator

RENDER_KINDS = frozenset({"index", "assign", "send", "recv", "go", "defer"})


def _chunks(obj) -> Iterator[tuple[str, object]]:
    if hasattr(obj, "c_repr_chunks"):
        yield from obj.c_repr_chunks()
    else:
        yield str(obj), obj


def _call_chunks(func, args, node) -> Iterator[tuple[str, object]]:
    yield from _chunks(func)
    yield "(", node
    for i, arg in enumerate(args):
        if i:
            yield ", ", None
        yield from _chunks(arg)
    yield ")", node


def render_builtin_call(call) -> Iterator[tuple[str, object]] | None:
    """
    Chunks for a codegen call node carrying a ``go_render`` tag, or None when the node is a regular call.
    """
    tags = getattr(call, "tags", None)
    kind = tags.get("go_render") if hasattr(tags, "get") else None
    if kind not in RENDER_KINDS:
        return None
    return _render(kind, list(call.args), call)


def _render(kind: str, args: list, node) -> Iterator[tuple[str, object]]:
    if kind == "index" and len(args) == 2:
        yield from _chunks(args[0])
        yield "[", node
        yield from _chunks(args[1])
        yield "]", node
    elif kind == "assign" and len(args) == 3:
        yield from _chunks(args[0])
        yield "[", node
        yield from _chunks(args[1])
        yield "] = ", node
        yield from _chunks(args[2])
    elif kind == "send" and len(args) == 2:
        yield from _chunks(args[0])
        yield " <- ", node
        yield from _chunks(args[1])
    elif kind == "recv" and len(args) == 1:
        yield "<-", node
        yield from _chunks(args[0])
    elif kind in ("go", "defer") and args:
        yield f"{kind} ", node
        yield from _call_chunks(args[0], args[1:], node)
    else:
        yield f"{kind}", node
        yield "(", node
        for i, arg in enumerate(args):
            if i:
                yield ", ", None
            yield from _chunks(arg)
        yield ")", node

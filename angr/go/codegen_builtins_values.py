"""
Rendering of builtin-call expressions produced by GoBuiltinRewriter that are not plain ``name(args)``: slice
expressions (``s[i:j]``) and calls that carry a comment about what could not be recovered.
"""

from __future__ import annotations

from collections.abc import Iterator


def call_tag(call, name: str, default=None):
    """A tag of a codegen call node; tags may be a dict or the AIL ``Tags`` mapping."""
    tags = call.tags
    if tags is None or not hasattr(tags, "get"):
        return default
    return tags.get(name, default)


def render_builtin_call_value(call) -> Iterator | None:
    """Chunks for ``call`` (a GoFunctionCall) when it needs special rendering, None otherwise."""
    if not isinstance(call.callee_target, str):
        return None
    shape = call_tag(call, "go_slice")
    if shape is not None:
        return _slice_chunks(call, shape)
    comment = call_tag(call, "go_comment")
    if comment is not None:
        return _commented_call_chunks(call, comment)
    return None


def _slice_chunks(call, shape: str) -> Iterator:
    from angr.analyses.decompiler.structured_codegen.go import (  # pylint:disable=import-outside-toplevel
        GoClosingObject,
        GoExpression,
    )

    base, *bounds = call.args
    low = high = None
    if shape == "[i:j]":
        low, high = bounds
    elif shape == "[i:]":
        (low,) = bounds
    else:
        (high,) = bounds
    yield from GoExpression._try_c_repr_chunks(base)
    bracket = GoClosingObject("[")
    yield "[", bracket
    if low is not None:
        yield from GoExpression._try_c_repr_chunks(low)
    yield ":", None
    if high is not None:
        yield from GoExpression._try_c_repr_chunks(high)
    yield "]", bracket


def _commented_call_chunks(call, comment: str) -> Iterator:
    from angr.analyses.decompiler.structured_codegen.go import (  # pylint:disable=import-outside-toplevel
        GoClosingObject,
        GoExpression,
    )

    yield call.callee_target, call
    paren = GoClosingObject("(")
    yield "(", paren
    items = [*(str(t) for t in call_tag(call, "go_type_args", ())), *call.args]
    for i, item in enumerate(items):
        if i:
            yield ", ", None
        if isinstance(item, str):
            yield item, None
        else:
            yield from GoExpression._try_c_repr_chunks(item)
    yield f" /* {comment} */", None
    yield ")", paren

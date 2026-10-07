"""JSON round-trip for the plain-data subset of the pattern DSL.

Patterns are frozen dataclasses of ints, strings, sets and other patterns, which
serialize naturally, plus a few callables (``PConst.pred``, ``KnownPattern.where``,
``binary_guard``, ``returnty_factory``) which do not. The built-in pattern library
uses those callables; a pattern authored in a UI never does. The codec covers the
former's data and refuses the latter by name, so a pattern that cannot round-trip
says so instead of coming back subtly different.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from angr.ailment.expression import VirtualVariableCategory

from . import dsl
from .pattern import CppRef, KnownPattern, PatternParam

# every node class the codec knows, by its wire name
NODE_CLASSES: dict[str, type[dsl.PatternNode]] = {
    cls.__name__: cls
    for cls in (
        dsl.PAny,
        dsl.PVVar,
        dsl.PConst,
        dsl.PBinOp,
        dsl.PUnaryOp,
        dsl.PConv,
        dsl.PReinterpret,
        dsl.PExtract,
        dsl.PLoad,
        dsl.PCall,
        dsl.PCallResult,
        dsl.PDefOf,
        dsl.PField,
        dsl.PStackField,
        dsl.PPhi,
        dsl.PITE,
        dsl.PChoice,
        dsl.PAssign,
        dsl.PStore,
        dsl.PCallStmt,
        dsl.PCondJump,
        dsl.PAnyStmt,
        dsl.PReturn,
        dsl.PStmtSeq,
        dsl.PBlockPat,
        dsl.PGraphPat,
    )
}

# fields whose sequences are lists rather than tuples on the Python side
_LIST_FIELDS = frozenset({"edges"})


class NotSerializableError(ValueError):
    """The pattern holds a value (a callable) that has no JSON form."""


def _encode(value: Any, where: str) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dsl.PatternNode):
        return node_to_dict(value)
    if isinstance(value, VirtualVariableCategory):
        return {"category": value.name}
    if isinstance(value, CppRef):
        return {"cpp": value.unique_name, "ptr": value.ptr}
    if isinstance(value, PatternParam):
        return {f.name: _encode(getattr(value, f.name), f"{where}.{f.name}") for f in dataclasses.fields(value)}
    if isinstance(value, frozenset):
        items = [_encode(v, where) for v in value]
        return {"set": sorted(items, key=json.dumps)}
    if isinstance(value, (tuple, list)):
        return [_encode(v, where) for v in value]
    if isinstance(value, dict):
        return {k: _encode(v, f"{where}[{k}]") for k, v in value.items()}
    if callable(value):
        raise NotSerializableError(f"{where} is a callable and has no JSON form")
    raise NotSerializableError(f"{where} holds a {type(value).__name__}, which the codec does not know")


def _decode(value: Any, field_name: str) -> Any:
    if isinstance(value, dict):
        if "kind" in value:
            return node_from_dict(value)
        if "set" in value:
            return frozenset(_decode(v, field_name) for v in value["set"])
        if "category" in value:
            return getattr(VirtualVariableCategory, value["category"])
        if "cpp" in value:
            return CppRef(value["cpp"], value["ptr"])
        if field_name == "params[]":
            return PatternParam(**{k: _decode(v, k) for k, v in value.items()})
        return {k: _decode(v, field_name) for k, v in value.items()}
    if isinstance(value, list):
        # only the outer sequence of a list field is a list; its pairs stay tuples
        items = [_decode(v, f"{field_name}[]") for v in value]
        return items if field_name in _LIST_FIELDS else tuple(items)
    return value


def node_to_dict(node: dsl.PatternNode) -> dict[str, Any]:
    """A JSON-ready dict for one pattern node and everything under it."""
    kind = type(node).__name__
    if kind not in NODE_CLASSES:
        raise NotSerializableError(f"{kind} is not a pattern node the codec knows")
    out: dict[str, Any] = {"kind": kind}
    for f in dataclasses.fields(node):  # type: ignore[arg-type]
        out[f.name] = _encode(getattr(node, f.name), f"{kind}.{f.name}")
    return out


def node_from_dict(data: dict[str, Any]) -> dsl.PatternNode:
    """The inverse of :func:`node_to_dict`."""
    kind = data["kind"]
    try:
        cls = NODE_CLASSES[kind]
    except KeyError:
        raise NotSerializableError(f"unknown pattern node kind {kind!r}") from None
    kwargs = {k: _decode(v, k) for k, v in data.items() if k != "kind"}
    if cls is dsl.PChoice:
        # the one node with a varargs constructor
        return dsl.PChoice(*kwargs["alternatives"])
    return cls(**kwargs)


def known_pattern_to_dict(pattern: KnownPattern) -> dict[str, Any]:
    """A JSON-ready dict for a whole KnownPattern. Refuses callables by name."""
    return {f.name: _encode(getattr(pattern, f.name), f"KnownPattern.{f.name}") for f in dataclasses.fields(pattern)}


def known_pattern_from_dict(data: dict[str, Any]) -> KnownPattern:
    """The inverse of :func:`known_pattern_to_dict`."""
    return KnownPattern(**{k: _decode(v, k) for k, v in data.items()})


def dumps(pattern: KnownPattern | dsl.PatternNode, **json_kwargs) -> str:
    data = known_pattern_to_dict(pattern) if isinstance(pattern, KnownPattern) else node_to_dict(pattern)
    return json.dumps(data, **json_kwargs)


def loads(text: str) -> KnownPattern | dsl.PatternNode:
    data = json.loads(text)
    return node_from_dict(data) if "kind" in data else known_pattern_from_dict(data)

"""Bridge between pattern-DSL nodes and the tokenizer's shape alphabet.

The fuzzy matcher aligns *shapes* (see :mod:`.tokenizer`), while a user-authored
pattern is a tree of :mod:`~angr.analyses.decompiler.known_patterns.dsl` nodes.
This module renders a node into the same alphabet, so a template can seed and
score against a token stream:

* :func:`shape_of` gives the one shape a fully concrete node stands for, or None
  when the node has a wildcard anywhere and stands for many.
* :func:`match_shape` says how well a node fits a stream token's shape: exactly,
  up to operator class, or not at all. Wildcards accept anything.

Both mirror :class:`~.tokenizer.AILCanonicalizer` rule for rule under the
:data:`TEMPLATE_TOKENIZER` settings, and ``tests/analyses/test_pattern_template.py``
checks the mirror against every statement of a real function.
"""

from __future__ import annotations

import re
from enum import IntEnum

from angr.analyses.decompiler.known_patterns import dsl

from .tokenizer import _OP_CLASSES

#: tokenizer settings a template is rendered under; a stream to search must use them
TEMPLATE_TOKENIZER: dict = {
    "max_depth": 5,
    "keep_vvar_category": False,
    "keep_sizes": True,
    "const_mode": "abstract",
    "skip_conversions": True,
    # labels and phis are never pattern statements (the exact matcher steps over them
    # too); left in the stream, each one is a gap every template has to pay for
    "skip_labels": True,
    "skip_phis": True,
}

_MAX_DEPTH = TEMPLATE_TOKENIZER["max_depth"]
_CALL_HEAD = re.compile(r"Call\[(.*)\]/(\d+)$")
_CONST_HEAD = re.compile(r"C(A|-?\d+)?$")

#: a shape string parsed into ``(head, children)``
ShapeTree = tuple[str, tuple["ShapeTree", ...]]


class Fit(IntEnum):
    """How well a node fits a shape. Ordered so ``min`` combines children."""

    NONE = 0
    KLASS = 1
    EXACT = 2


def parse_shape(shape: str) -> ShapeTree:
    """``"Asn(V,Add(V,C))"`` -> ``("Asn", (("V", ()), ("Add", (("V", ()), ("C", ())))))``."""
    pos = 0

    def node() -> ShapeTree:
        nonlocal pos
        start = pos
        depth = 0
        # a head runs to the next top-level "(" "," or ")", brackets included
        while pos < len(shape):
            c = shape[pos]
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
            elif depth == 0 and c in "(,)":
                break
            pos += 1
        head = shape[start:pos]
        children: list[ShapeTree] = []
        if pos < len(shape) and shape[pos] == "(":
            pos += 1
            while True:
                children.append(node())
                if shape[pos] == ",":
                    pos += 1
                    continue
                assert shape[pos] == ")", shape
                pos += 1
                break
        return head, tuple(children)

    tree = node()
    if pos != len(shape):
        raise ValueError(f"trailing text in shape {shape!r}")
    return tree


#
# shape_of: the exact shape of a concrete node
#


def shape_of(node: dsl.PatternNode) -> str | None:
    """The shape a fully concrete node renders to, or None if it has a wildcard."""
    if isinstance(node, dsl.PAssign):
        return _join("Asn", (node.dst, node.src), 1)
    if isinstance(node, dsl.PStore):
        return None if node.size is None else _join(f"St{node.size}", (node.addr, node.value), 1)
    if isinstance(node, dsl.PCallStmt):
        call = _expr_shape(node.call, 1)
        if call is None:
            return None
        if node.dst is None:
            return f"SE({call})"
        dst = _expr_shape(node.dst, 1)
        return None if dst is None else f"Asn({dst},{call})"
    if isinstance(node, dsl.PReturn):
        return None if node.values is None else _join(f"Ret{len(node.values)}", node.values, 1)
    # PCondJump carries no branch directions, PAnyStmt nothing at all
    return None


def _join(head: str, operands: tuple[dsl.PatternExpr, ...], depth: int) -> str | None:
    parts = []
    for operand in operands:
        part = _expr_shape(operand, depth)
        if part is None:
            return None
        parts.append(part)
    return f"{head}({','.join(parts)})"


def _expr_shape(node: dsl.PatternExpr, depth: int) -> str | None:
    if depth > _MAX_DEPTH:
        return "?"
    d = depth + 1
    if isinstance(node, dsl.PVVar):
        return "V"
    if isinstance(node, dsl.PConst):
        return "C"
    if isinstance(node, dsl.PBinOp):
        return None if not isinstance(node.op, str) else _join(node.op, node.operands, d)
    if isinstance(node, dsl.PUnaryOp):
        return None if not isinstance(node.op, str) else _join(node.op, (node.operand,), d)
    if isinstance(node, dsl.PLoad):
        return None if node.size is None else _join(f"Ld{node.size}", (node.addr,), d)
    if isinstance(node, dsl.PConv):
        # conversions are skipped on both sides
        return _expr_shape(node.operand, depth)
    if isinstance(node, dsl.PExtract):
        return None if node.bits is None else _join(f"Ext{node.bits}", (node.operand, dsl.PConst()), d)
    if isinstance(node, dsl.PCall):
        if len(node.names) != 1 or node.args is None:
            return None
        return f"Call[{next(iter(node.names))}]/{len(node.args)}"
    if isinstance(node, dsl.PField):
        return "V" if node.offset == 0 else _join("Add", (dsl.PVVar(), dsl.PConst()), d)
    if isinstance(node, dsl.PITE):
        return _join("ITE", (node.cond, node.iftrue, node.iffalse), d)
    # PAny, PPhi (unknown arity), PChoice, PCallResult, PDefOf, PStackField
    return None


#
# match_shape: how well a node fits a token's shape
#


def match_shape(node: dsl.PatternNode, tree: ShapeTree) -> Fit:
    """How well ``node`` fits the shape ``tree`` of one token."""
    head, children = tree
    if isinstance(node, dsl.PAnyStmt):
        return Fit.EXACT
    if isinstance(node, dsl.PAssign):
        return _fit_children(head == "Asn", (node.dst, node.src), children, 1)
    if isinstance(node, dsl.PStore):
        ok = head.startswith("St") and (node.size is None or head == f"St{node.size}")
        return _fit_children(ok, (node.addr, node.value), children, 1)
    if isinstance(node, dsl.PCondJump):
        return _fit_children(head.startswith("CJ"), (node.condition,), children, 1)
    if isinstance(node, dsl.PReturn):
        if not head.startswith("Ret"):
            return Fit.NONE
        return (
            Fit.EXACT
            if node.values is None
            else _fit_children(head == f"Ret{len(node.values)}", node.values, children, 1)
        )
    if isinstance(node, dsl.PCallStmt):
        if head == "SE":
            return Fit.NONE if node.dst is not None else _fit_children(True, (node.call,), children, 1)
        if head == "Asn" and len(children) == 2:
            dst = Fit.EXACT if node.dst is None else _fit_expr(node.dst, children[0], 2)
            return min(dst, _fit_expr(node.call, children[1], 2))
        return Fit.NONE
    raise TypeError(f"{type(node).__name__} is not a statement pattern")


def _fit_children(head_ok: bool, operands: tuple[dsl.PatternExpr, ...], children: tuple, depth: int) -> Fit:
    if not head_ok or len(operands) != len(children):
        return Fit.NONE
    fit = Fit.EXACT
    for operand, child in zip(operands, children):
        fit = min(fit, _fit_expr(operand, child, depth + 1))
        if fit is Fit.NONE:
            break
    return fit


def _op_fit(op: str | frozenset[str], head: str) -> Fit:
    ops = {op} if isinstance(op, str) else op
    if head in ops:
        return Fit.EXACT
    head_class = _OP_CLASSES.get(head)
    if head_class is not None and all(_OP_CLASSES.get(o) == head_class for o in ops):
        return Fit.KLASS
    return Fit.NONE


def _fit_expr(node: dsl.PatternExpr, tree: ShapeTree, depth: int) -> Fit:
    head, children = tree
    if head == "?" or isinstance(node, dsl.PAny):
        # the token's rendering was cut off here, or the node does not care
        return Fit.EXACT
    if isinstance(node, dsl.PVVar):
        return Fit.EXACT if head.startswith("V") and len(head) <= 2 and not children else Fit.NONE
    if isinstance(node, dsl.PConst):
        return Fit.EXACT if _CONST_HEAD.match(head) and not children else Fit.NONE
    if isinstance(node, dsl.PBinOp):
        fit = _op_fit(node.op, head)
        return Fit.NONE if fit is Fit.NONE else min(fit, _fit_children(True, node.operands, children, depth))
    if isinstance(node, dsl.PUnaryOp):
        fit = _op_fit(node.op, head)
        return Fit.NONE if fit is Fit.NONE else min(fit, _fit_children(True, (node.operand,), children, depth))
    if isinstance(node, dsl.PLoad):
        ok = head.startswith("Ld") and (node.size is None or head == f"Ld{node.size}")
        return _fit_children(ok, (node.addr,), children, depth)
    if isinstance(node, dsl.PConv):
        return _fit_expr(node.operand, tree, depth)
    if isinstance(node, dsl.PExtract):
        ok = head.startswith("Ext") and (node.bits is None or head == f"Ext{node.bits}")
        return _fit_children(ok, (node.operand, dsl.PAny()), children, depth)
    if isinstance(node, dsl.PCall):
        m = _CALL_HEAD.match(head)
        if m is None or (node.args is not None and len(node.args) != int(m.group(2))):
            return Fit.NONE
        if not node.names or m.group(1) in node.names:
            return Fit.EXACT
        # a stream tokenized without a knowledge base names no callee
        return Fit.KLASS if m.group(1).startswith("@") or m.group(1) == "*" else Fit.NONE
    if isinstance(node, dsl.PCallResult):
        # the call's result is read: a variable, or the call where it is consumed in place
        if head.startswith("V") and not children:
            return Fit.EXACT
        return _fit_expr(dsl.PCall(node.names), tree, depth)
    if isinstance(node, dsl.PDefOf):
        # the definition is chased through a variable, or is written out in place
        if head.startswith("V") and not children:
            return Fit.EXACT
        return _fit_expr(node.inner, tree, depth)
    if isinstance(node, dsl.PField):
        if node.offset == 0:
            return Fit.EXACT if head.startswith("V") and not children else Fit.NONE
        return _fit_children(head == "Add", (dsl.PVVar(), dsl.PConst()), children, depth)
    if isinstance(node, dsl.PStackField):
        return Fit.EXACT
    if isinstance(node, dsl.PPhi):
        return Fit.EXACT if head.startswith("Phi") else Fit.NONE
    if isinstance(node, dsl.PITE):
        return _fit_children(head == "ITE", (node.cond, node.iftrue, node.iffalse), children, depth)
    if isinstance(node, dsl.PChoice):
        return max((_fit_expr(alt, tree, depth) for alt in node.alternatives), default=Fit.NONE)
    raise TypeError(f"{type(node).__name__} is not an expression pattern")

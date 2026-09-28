"""Edit a pattern the way a visual editor does: by node, with undo.

Pattern nodes are frozen, so an edit rebuilds the spine from the root down to the
node it touches and leaves everything else shared. A node is addressed by its
*path*, the sequence of field names, tuple indices and block labels that leads to
it from the root, which is what a UI holds on to across rebuilds.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from . import dsl
from .pattern import KnownPattern, PatternParam, TypeRef
from .serialize import known_pattern_from_dict, known_pattern_to_dict

#: how a node is reached from the pattern root: field names, tuple indices, block labels
NodePath = tuple[str | int, ...]

#: the three ways a leaf statement takes part in matching
LEAF_MODES = ("required", "optional", "wildcard")


class PatternEditor:
    """A :class:`KnownPattern` under edit."""

    def __init__(self, pattern: KnownPattern):
        self.pattern = pattern
        self._undo: list[KnownPattern] = []

    #
    # navigation
    #

    def node_at(self, path: NodePath) -> dsl.PatternNode:
        node: Any = self.pattern.pattern
        for step in path:
            node = _child(node, step)
        return node

    def children(self, path: NodePath) -> list[tuple[NodePath, dsl.PatternNode]]:
        """The pattern nodes directly under the node at ``path``, in field order."""
        node = self.node_at(path)
        out: list[tuple[NodePath, dsl.PatternNode]] = []
        if isinstance(node, dsl.PGraphPat):
            for label in _block_order(node):
                out.append(((*path, label), node.blocks[label]))
            return out
        for f in dataclasses.fields(node):  # type: ignore[arg-type]
            value = getattr(node, f.name)
            if isinstance(value, dsl.PatternNode):
                out.append(((*path, f.name), value))
            elif isinstance(value, tuple):
                for i, item in enumerate(value):
                    if isinstance(item, dsl.PatternNode):
                        out.append(((*path, f.name, i), item))
        return out

    def leaves(self) -> list[tuple[NodePath, dsl.LeafStmt]]:
        """Every leaf statement with its path, in the order the matcher aligns them."""
        out: list[tuple[NodePath, dsl.LeafStmt]] = []

        def walk(path: NodePath, node: dsl.PatternNode) -> None:
            if isinstance(node, (dsl.PGraphPat, dsl.PBlockPat, dsl.PStmtSeq)):
                for child_path, child in self.children(path):
                    walk(child_path, child)
            elif isinstance(node, (dsl.PAssign, dsl.PStore, dsl.PCallStmt, dsl.PCondJump, dsl.PAnyStmt)):
                out.append((path, node))

        walk((), self.pattern.pattern)
        return out

    @staticmethod
    def leaf_mode(leaf: dsl.LeafStmt) -> str:
        if isinstance(leaf, dsl.PAnyStmt):
            return "wildcard"
        return "optional" if leaf.optional else "required"

    #
    # edits
    #

    def replace_node(self, path: NodePath, new_node: dsl.PatternNode) -> None:
        self._commit(dataclasses.replace(self.pattern, pattern=_rebuild(self.pattern.pattern, path, new_node)))

    def set_leaf_mode(self, path: NodePath, mode: str) -> None:
        """``required`` or ``optional`` keep the statement's shape; ``wildcard`` drops it for a
        PAnyStmt that keeps the weight and optionality. Undo brings the shape back."""
        leaf = self.node_at(path)
        if mode not in LEAF_MODES:
            raise ValueError(f"unknown leaf mode {mode!r}")
        if mode == "wildcard":
            if not isinstance(leaf, dsl.PAnyStmt):
                self.replace_node(path, dsl.PAnyStmt(optional=leaf.optional, weight=leaf.weight))
            return
        if isinstance(leaf, dsl.PAnyStmt):
            self.replace_node(path, dataclasses.replace(leaf, optional=mode == "optional"))
            return
        self.replace_node(path, dataclasses.replace(leaf, optional=mode == "optional"))

    def set_leaf_weight(self, path: NodePath, weight: float) -> None:
        self.replace_node(path, dataclasses.replace(self.node_at(path), weight=float(weight)))

    def set_expr_wildcard(self, path: NodePath) -> None:
        """Replace an expression node by PAny, keeping its capture name and width if it had them."""
        node = self.node_at(path)
        if not isinstance(node, dsl.PatternExpr):
            raise TypeError(f"{type(node).__name__} is not an expression")
        name = node.name if isinstance(node, _NAMED) else None
        bits = node.bits if isinstance(node, (dsl.PVVar, dsl.PConst, dsl.PPhi, dsl.PAny)) else None
        self.replace_node(path, dsl.PAny(name=name, bits=bits))

    def set_const(self, path: NodePath, value: int | None, bits: int | None = None) -> None:
        node = self.node_at(path)
        if not isinstance(node, dsl.PConst):
            raise TypeError(f"{type(node).__name__} is not a constant")
        self.replace_node(path, dataclasses.replace(node, value=value, bits=bits, pred=None))

    def set_vvar(self, path: NodePath, bits: int | None, categories: frozenset | None) -> None:
        node = self.node_at(path)
        if not isinstance(node, dsl.PVVar):
            raise TypeError(f"{type(node).__name__} is not a variable")
        self.replace_node(path, dataclasses.replace(node, bits=bits, categories=categories))

    def set_load_size(self, path: NodePath, size: int | None) -> None:
        node = self.node_at(path)
        if isinstance(node, (dsl.PLoad, dsl.PStore)):
            self.replace_node(path, dataclasses.replace(node, size=size))
        else:
            raise TypeError(f"{type(node).__name__} has no size")

    def set_ops(self, path: NodePath, ops: str | frozenset[str]) -> None:
        node = self.node_at(path)
        if not isinstance(node, (dsl.PBinOp, dsl.PUnaryOp)):
            raise TypeError(f"{type(node).__name__} has no operator")
        self.replace_node(path, dataclasses.replace(node, op=ops))

    def loosen_constants(self) -> int:
        """Drop the value of every pinned constant, as one undoable edit. Copies of an idiom
        that differ only in their constants, a decryption loop's keys and sizes, say, are
        exactly what a fuzzy pattern is for, and pinning them is what a lifted pattern
        starts out doing. Returns how many constants were loosened."""
        paths: list[NodePath] = []

        def walk(path: NodePath) -> None:
            for child_path, child in self.children(path):
                if isinstance(child, dsl.PConst) and child.value is not None:
                    paths.append(child_path)
                walk(child_path)

        walk(())
        if not paths:
            return 0
        root = self.pattern.pattern
        for path in paths:
            node = self.node_at(path)
            root = _rebuild(root, path, dataclasses.replace(node, value=None, pred=None))
        self._commit(dataclasses.replace(self.pattern, pattern=root))
        return len(paths)

    def cut_depth(self, max_depth: int = 5) -> int:
        """Replace every expression deeper than ``max_depth`` below its statement by a
        wildcard, as one undoable edit. Shape search is cut at that depth, so anything below
        it never affects where an occurrence is found; it only bites at verification, where
        two copies of an idiom that differ in how they spell a deep subexpression part ways.
        Returns how many subtrees were cut."""
        cuts: list[NodePath] = []

        def walk(path: NodePath, depth: int) -> None:
            for child_path, child in self.children(path):
                if isinstance(child, dsl.PatternExpr):
                    if depth + 1 > max_depth and not isinstance(child, dsl.PAny):
                        cuts.append(child_path)
                        continue
                    walk(child_path, depth + 1)
                else:
                    walk(child_path, 0)

        walk((), 0)
        if not cuts:
            return 0
        root = self.pattern.pattern
        for path in cuts:
            node = self.node_at(path)
            # a leaf keeps its capture name: the wildcard still binds the same thing. An
            # inner node must not: a named wildcard binds the whole subtree, and a
            # parameter's other uses bind the variable, so the two could never unify
            name = node.name if isinstance(node, (dsl.PVVar, dsl.PConst, dsl.PAny)) else None
            root = _rebuild(root, path, dsl.PAny(name=name))
        self._commit(dataclasses.replace(self.pattern, pattern=root))
        return len(cuts)

    def loosen_interior_captures(self) -> int:
        """Drop the names of interior captures (the ``_t*`` ones the generator gives values
        defined inside the selection), as one undoable edit. A name ties every use to one
        variable; a copy that routes the same value through another register then fails
        to verify. Parameters keep their names. Returns how many captures were loosened."""
        params = {p.capture for p in self.pattern.params}
        paths: list[NodePath] = []

        def walk(path: NodePath) -> None:
            for child_path, child in self.children(path):
                if (
                    isinstance(child, _NAMED)
                    and child.name
                    and child.name not in params
                    and child.name.startswith("_t")
                ):
                    paths.append(child_path)
                walk(child_path)

        walk(())
        if not paths:
            return 0
        root = self.pattern.pattern
        for path in paths:
            root = _rebuild(root, path, dataclasses.replace(self.node_at(path), name=None))
        self._commit(dataclasses.replace(self.pattern, pattern=root))
        return len(paths)

    def set_call_name(self, call_name: str) -> None:
        self._commit(dataclasses.replace(self.pattern, call_name=call_name))

    def set_name(self, name: str) -> None:
        self._commit(dataclasses.replace(self.pattern, name=name))

    def set_display_name(self, display_name: str) -> None:
        self._commit(dataclasses.replace(self.pattern, display_name=display_name))

    def set_returnty(self, returnty: TypeRef | None) -> None:
        self._commit(dataclasses.replace(self.pattern, returnty=returnty))

    def set_param_type(self, capture: str, typeref: TypeRef | None) -> None:
        params = tuple(dataclasses.replace(p, type=typeref) if p.capture == capture else p for p in self.pattern.params)
        if params == self.pattern.params:
            raise KeyError(f"no parameter captures {capture!r}")
        self._commit(dataclasses.replace(self.pattern, params=params))

    def add_param(self, capture: str, typeref: TypeRef | None = None) -> None:
        if any(p.capture == capture for p in self.pattern.params):
            raise ValueError(f"parameter {capture!r} already exists")
        self._commit(dataclasses.replace(self.pattern, params=(*self.pattern.params, PatternParam(capture, typeref))))

    def remove_param(self, capture: str) -> None:
        params = tuple(p for p in self.pattern.params if p.capture != capture)
        if len(params) == len(self.pattern.params):
            raise KeyError(f"no parameter captures {capture!r}")
        self._commit(dataclasses.replace(self.pattern, params=params))

    #
    # undo and persistence
    #

    @property
    def can_undo(self) -> bool:
        return bool(self._undo)

    def undo(self) -> bool:
        if not self._undo:
            return False
        self.pattern = self._undo.pop()
        return True

    def to_dict(self) -> dict[str, Any]:
        return known_pattern_to_dict(self.pattern)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PatternEditor:
        return cls(known_pattern_from_dict(data))

    def _commit(self, pattern: KnownPattern) -> None:
        self._undo.append(self.pattern)
        self.pattern = pattern


#
# labels for a UI
#


def describe(node: dsl.PatternNode) -> str:
    """A short label for a node: what it is and what it constrains."""
    if isinstance(node, dsl.PAnyStmt):
        return "any statement"
    if isinstance(node, dsl.PAssign):
        return "assign"
    if isinstance(node, dsl.PStore):
        return f"store{node.size}" if node.size is not None else "store"
    if isinstance(node, dsl.PCallStmt):
        return "call statement"
    if isinstance(node, dsl.PCondJump):
        return "if"
    if isinstance(node, dsl.PStmtSeq):
        return f"sequence of {len(node.stmts)}"
    if isinstance(node, dsl.PBlockPat):
        return f"block {node.label}"
    if isinstance(node, dsl.PGraphPat):
        return f"graph of {len(node.blocks)} blocks"
    if isinstance(node, dsl.PAny):
        return _named("any", node.name)
    if isinstance(node, dsl.PVVar):
        return _named("var", node.name) + (f":{node.bits}" if node.bits is not None else "")
    if isinstance(node, dsl.PConst):
        if node.value is not None:
            return _named(f"const {node.value:#x}" if node.value >= 0 else f"const {node.value}", node.name)
        return _named("const *", node.name)
    if isinstance(node, (dsl.PBinOp, dsl.PUnaryOp)):
        ops = node.op if isinstance(node.op, str) else "|".join(sorted(node.op))
        return _named(ops, node.name)
    if isinstance(node, dsl.PLoad):
        return _named(f"load{node.size}" if node.size is not None else "load", node.name)
    if isinstance(node, dsl.PConv):
        return "convert"
    if isinstance(node, dsl.PExtract):
        return "extract"
    if isinstance(node, dsl.PCall):
        return _named("call " + ("|".join(sorted(node.names)) or "*"), node.name)
    if isinstance(node, dsl.PCallResult):
        return _named("result of " + ("|".join(sorted(node.names)) or "*"), node.name)
    if isinstance(node, dsl.PDefOf):
        return _named("definition", node.name)
    if isinstance(node, dsl.PField):
        return _named(f"{node.base}+{node.offset:#x}", node.name)
    if isinstance(node, dsl.PStackField):
        return _named(f"stack {node.base}{node.offset:+#x}", node.name)
    if isinstance(node, dsl.PPhi):
        return _named("phi", node.name)
    if isinstance(node, dsl.PITE):
        return _named("?:", node.name)
    if isinstance(node, dsl.PChoice):
        return f"one of {len(node.alternatives)}"
    return type(node).__name__


def _named(label: str, name: str | None) -> str:
    return f"{label} [{name}]" if name else label


#
# path plumbing
#

_NAMED = (
    dsl.PAny,
    dsl.PVVar,
    dsl.PConst,
    dsl.PBinOp,
    dsl.PUnaryOp,
    dsl.PConv,
    dsl.PExtract,
    dsl.PLoad,
    dsl.PCall,
    dsl.PCallResult,
    dsl.PDefOf,
    dsl.PField,
    dsl.PStackField,
    dsl.PPhi,
    dsl.PITE,
)


def _block_order(graph: dsl.PGraphPat) -> list[str]:
    """Blocks in reverse post-order from the entry, the order the matcher flattens them."""
    succs: dict[str, list[str]] = {label: [] for label in graph.blocks}
    for src, dst in graph.edges:
        if dst in graph.blocks:
            succs[src].append(dst)
    post: list[str] = []
    seen = {graph.entry}
    stack = [(graph.entry, sorted(succs[graph.entry]))]
    while stack:
        _label, rest = stack[-1]
        while rest:
            nxt = rest.pop(0)
            if nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, sorted(succs[nxt])))
                break
        else:
            post.append(stack.pop()[0])
    return post[::-1]


def _child(node: Any, step: str | int) -> Any:
    if isinstance(node, dsl.PGraphPat) and isinstance(step, str) and step in node.blocks:
        return node.blocks[step]
    if isinstance(step, int):
        return node[step]
    return getattr(node, step)


def _rebuild(node: Any, path: NodePath, new_node: dsl.PatternNode) -> Any:
    """``node`` with the value at ``path`` replaced, sharing everything off the path."""
    if not path:
        return new_node
    step, rest = path[0], path[1:]
    if isinstance(node, dsl.PGraphPat) and isinstance(step, str) and step in node.blocks:
        blocks = dict(node.blocks)
        blocks[step] = _rebuild(blocks[step], rest, new_node)
        return dsl.PGraphPat(blocks=blocks, edges=node.edges, entry=node.entry)
    if isinstance(node, tuple):
        assert isinstance(step, int)
        items = list(node)
        items[step] = _rebuild(items[step], rest, new_node)
        return tuple(items)
    assert isinstance(step, str)
    value = _rebuild(getattr(node, step), rest, new_node)
    if isinstance(node, dsl.PChoice):
        return dsl.PChoice(*value)
    return dataclasses.replace(node, **{step: value})

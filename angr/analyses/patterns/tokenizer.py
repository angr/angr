"""Turn an AIL graph into a linear token stream suitable for string algorithms.

The stream is what the fuzzy matcher in :mod:`.align` operates on. Every AIL
statement becomes exactly one token, canonicalized at three levels:

``shape``
    A depth-limited canonical rendering of the statement tree with constants,
    variable identities and addresses abstracted away. Two statements share a
    shape iff they are the "same operation" modulo those details. This is the
    exact-match key used for seeding.
``klass``
    ``shape`` with operators replaced by their class (ARITH/LOGIC/SHIFT/...).
    Used to give partial credit when two statements differ only in which
    arithmetic operator they use.
``bag``
    Multiset of operator names at every depth, for an optional graded score.

Keeping the operator name in ``shape`` and folding it only in ``klass`` is
deliberate: the fuzziness belongs in the substitution score, not in the token,
so that ``Add`` vs ``Sub`` costs a little while ``Add`` vs ``Store`` costs a lot.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr.ailment import expression as ex
from angr.ailment import statement as st

if TYPE_CHECKING:
    import networkx

    from angr.ailment import Block
    from angr.knowledge_base import KnowledgeBase

_l = logging.getLogger(__name__)

Address = tuple[int, "int | None"]

_OP_CLASSES: dict[str, str] = {}
for _cls, _ops in {
    "ARITH": ("Add", "Sub", "Mul", "Mull", "Div", "DivMod", "Mod", "Neg"),
    "LOGIC": ("Xor", "And", "Or", "Not", "BitwiseNeg", "LogicalAnd", "LogicalOr", "LogicalNot"),
    "SHIFT": ("Shl", "Shr", "Sar", "Rol", "Ror"),
    "CMP": (
        "CmpEQ",
        "CmpNE",
        "CmpLT",
        "CmpLE",
        "CmpGT",
        "CmpGE",
        "CmpLTs",
        "CmpLEs",
        "CmpGTs",
        "CmpGEs",
    ),
}.items():
    for _op in _ops:
        _OP_CLASSES[_op] = _cls


@dataclass(frozen=True)
class TokenLoc:
    """Where a token came from."""

    block_addr: int
    block_idx: int | None
    stmt_idx: int
    block_pos: int
    ins_addr: int | None

    @property
    def block_loc(self) -> Address:
        return self.block_addr, self.block_idx


@dataclass
class TokenStream:
    """A linearized, canonicalized view of an AIL graph."""

    blocks: list[Block]
    block_span: dict[Address, tuple[int, int]]
    locs: list[TokenLoc]
    shapes: list[str]
    klasses: list[str]
    bags: list[Counter]
    shape_ids: list[int]
    klass_ids: list[int]
    shape_vocab: list[str] = field(default_factory=list)
    klass_vocab: list[str] = field(default_factory=list)
    klass_of_shape: list[int] = field(default_factory=list)
    #: the knowledge base the callee names were resolved against, for a verifier to reuse
    kb: KnowledgeBase | None = None

    def __len__(self) -> int:
        return len(self.shape_ids)

    def block_locs_in(self, start: int, end: int) -> list[Address]:
        """Block locations touched by tokens ``[start, end)``, in linearization order."""
        out: list[Address] = []
        seen: set[Address] = set()
        for loc in self.locs[start:end]:
            if loc.block_loc not in seen:
                seen.add(loc.block_loc)
                out.append(loc.block_loc)
        return out

    def covers_whole_block(self, start: int, end: int, block_loc: Address) -> bool:
        s, e = self.block_span[block_loc]
        return start <= s and e <= end

    def addr_range(self, start: int, end: int) -> tuple[int | None, int | None]:
        addrs = [loc.ins_addr for loc in self.locs[start:end] if loc.ins_addr is not None]
        return (min(addrs), max(addrs)) if addrs else (None, None)


def is_dephi_copy(stmt: st.Statement) -> bool:
    """A copy SSA destruction added: it does not exist at the stage the pattern pass runs at."""
    return bool(stmt.tags.get("dephi"))


def is_glue_shape(shape: str) -> bool:
    """An unconditional jump: control glue between blocks, not a statement an idiom is made of."""
    return shape in ("Jf", "Jb", "J?")


class AILCanonicalizer:
    """Renders AIL statements into canonical shape strings."""

    def __init__(
        self,
        *,
        max_depth: int = 5,
        keep_vvar_category: bool = True,
        keep_sizes: bool = True,
        const_mode: str = "abstract",
        kb: KnowledgeBase | None = None,
        block_pos: dict[Address, int] | None = None,
        loader=None,
        skip_conversions: bool = False,
    ):
        if const_mode not in ("abstract", "class", "exact"):
            raise ValueError(f"unknown const_mode {const_mode!r}")
        self.max_depth = max_depth
        # render through Convert/Reinterpret the way the pattern matcher looks through them
        self.skip_conversions = skip_conversions
        self.keep_vvar_category = keep_vvar_category
        self.keep_sizes = keep_sizes
        self.const_mode = const_mode
        self.kb = kb
        self.block_pos = block_pos or {}
        self.loader = loader

    #
    # public
    #

    def statement(self, stmt: st.Statement, cur_pos: int | None = None) -> str:
        return self._stmt(stmt, cur_pos)

    def bag(self, stmt: st.Statement, max_depth: int = 8) -> Counter:
        out: Counter = Counter()
        self._bag(stmt, 0, max_depth, out)
        return out

    @staticmethod
    def klass_of(shape: str) -> str:
        """Fold operator names in a shape string into operator classes."""
        out = []
        i = 0
        n = len(shape)
        while i < n:
            c = shape[i]
            if c.isalpha() or c == "_":
                j = i
                while j < n and (shape[j].isalnum() or shape[j] == "_"):
                    j += 1
                word = shape[i:j]
                out.append(_OP_CLASSES.get(word, word))
                i = j
            else:
                out.append(c)
                i += 1
        return "".join(out)

    #
    # internals
    #

    def _size(self, n: int) -> str:
        return str(n) if self.keep_sizes else ""

    def _const(self, c: ex.Const) -> str:
        if self.const_mode == "exact":
            return f"C{c.value}"
        if self.const_mode == "class":
            v = c.value
            if isinstance(v, int) and self.loader is not None and self.loader.find_object_containing(v) is not None:
                return "CA"
            return "C"
        return "C"

    def _call_target(self, call: ex.Call) -> str:
        name = getattr(call, "target_name", None)
        if name:
            return name
        target = call.target
        if isinstance(target, ex.Const) and self.kb is not None:
            func = self.kb.functions.function(addr=target.value)
            if func is not None:
                return func.name
        if isinstance(target, ex.Const):
            return f"@{target.value:x}"
        return "*"

    def _direction(self, target, target_idx, cur_pos: int | None) -> str:
        if cur_pos is None or not isinstance(target, ex.Const):
            return "?"
        pos = self.block_pos.get((target.value, target_idx))
        if pos is None:
            pos = self.block_pos.get((target.value, None))
        if pos is None:
            return "?"
        return "b" if pos <= cur_pos else "f"

    def _expr(self, o, depth: int) -> str:
        if depth > self.max_depth:
            return "?"
        d = depth + 1

        if isinstance(o, ex.Const):
            return self._const(o)
        if isinstance(o, ex.VirtualVariable):
            return f"V{o.category.name[0]}" if self.keep_vvar_category else "V"
        if isinstance(o, (ex.Register, ex.Tmp)):
            return "V?"
        if isinstance(o, ex.StackBaseOffset):
            return "SBO"
        if isinstance(o, ex.Load):
            return f"Ld{self._size(o.size)}({self._expr(o.addr, d)})"
        if isinstance(o, (ex.Convert, ex.Reinterpret)) and self.skip_conversions:
            return self._expr(o.operand, depth)
        if isinstance(o, ex.Convert):
            return f"Cv{o.from_bits}_{o.to_bits}({self._expr(o.operand, d)})"
        if isinstance(o, ex.Reinterpret):
            return f"Ri{o.from_bits}_{o.to_bits}({self._expr(o.operand, d)})"
        if isinstance(o, (ex.BinaryOp, ex.UnaryOp)):
            return f"{o.op}({','.join(self._expr(x, d) for x in o.operands)})"
        if isinstance(o, ex.Call):
            nargs = len(o.args) if o.args else 0
            return f"Call[{self._call_target(o)}]/{nargs}"
        if isinstance(o, ex.Phi):
            return f"Phi{len(o.src_and_vvars)}"
        if isinstance(o, ex.ITE):
            return f"ITE({self._expr(o.cond, d)},{self._expr(o.iftrue, d)},{self._expr(o.iffalse, d)})"
        if isinstance(o, ex.Extract):
            return f"Ext{o.bits}({self._expr(o.base, d)},{self._expr(o.offset, d)})"
        if isinstance(o, ex.Insert):
            return f"Ins({self._expr(o.base, d)},{self._expr(o.offset, d)},{self._expr(o.value, d)})"
        if isinstance(o, ex.DirtyExpression):
            return f"Dirty[{o.callee}]/{len(o.operands) if o.operands else 0}"
        if isinstance(o, ex.VEXCCallExpression):
            return f"CCall[{o.callee}]"
        if isinstance(o, ex.MultiStatementExpression):
            return f"MSE({self._expr(o.expr, d)})"
        if isinstance(o, ex.StringLiteral):
            return "Str"
        return type(o).__name__

    def _stmt(self, s: st.Statement, cur_pos: int | None) -> str:
        d = 1
        if isinstance(s, st.Assignment):
            return f"Asn({self._expr(s.dst, d)},{self._expr(s.src, d)})"
        if isinstance(s, st.WeakAssignment):
            return f"WAsn({self._expr(s.dst, d)},{self._expr(s.src, d)})"
        if isinstance(s, st.Store):
            return f"St{self._size(s.size)}({self._expr(s.addr, d)},{self._expr(s.data, d)})"
        if isinstance(s, st.ConditionalJump):
            t = self._direction(s.true_target, s.true_target_idx, cur_pos)
            f = self._direction(s.false_target, s.false_target_idx, cur_pos)
            return f"CJ{t}{f}({self._expr(s.condition, d)})"
        if isinstance(s, st.Jump):
            return f"J{self._direction(s.target, s.target_idx, cur_pos)}"
        if isinstance(s, st.Label):
            return "L"
        if isinstance(s, st.Return):
            exprs = s.ret_exprs or ()
            return f"Ret{len(exprs)}({','.join(self._expr(e, d) for e in exprs)})" if exprs else "Ret0"
        if isinstance(s, st.SideEffectStatement):
            return f"SE({self._expr(s.expr, d)})"
        if isinstance(s, st.CAS):
            return "CAS"
        if isinstance(s, st.DirtyStatement):
            return f"DirtyStmt({self._expr(s.dirty, d)})" if hasattr(s, "dirty") else "DirtyStmt"
        if isinstance(s, st.NoOp):
            return "NoOp"
        return type(s).__name__

    def _bag(self, o, depth: int, max_depth: int, out: Counter) -> None:
        if depth > max_depth:
            return
        d = depth + 1
        if isinstance(o, ex.Const):
            out["C"] += 1
            return
        if isinstance(o, (ex.VirtualVariable, ex.Register, ex.Tmp)):
            out["V"] += 1
            return
        if isinstance(o, (ex.BinaryOp, ex.UnaryOp)):
            out[o.op] += 1
            for x in o.operands:
                self._bag(x, d, max_depth, out)
            return
        out[type(o).__name__] += 1
        for attr in ("addr", "data", "src", "dst", "operand", "base", "value", "condition", "expr", "cond"):
            v = getattr(o, attr, None)
            if isinstance(v, ex.Expression):
                self._bag(v, d, max_depth, out)


def linearize(graph: networkx.DiGraph[Block], entry: Block) -> list[Block]:
    """Reverse post-order from ``entry``, deterministic, with unreachable blocks appended.

    RPO keeps single-entry regions contiguous, which is what the Outliner needs.
    """
    key = lambda b: (b.addr, -1 if b.idx is None else b.idx)

    seen = {entry}
    post: list[Block] = []
    stack: list[tuple[Block, list[Block]]] = [(entry, sorted(graph.successors(entry), key=key))]
    while stack:
        _node, succs = stack[-1]
        while succs:
            succ = succs.pop(0)
            if succ not in seen:
                seen.add(succ)
                stack.append((succ, sorted(graph.successors(succ), key=key)))
                break
        else:
            post.append(stack.pop()[0])
    order = post[::-1]
    order.extend(sorted((b for b in graph if b not in seen), key=key))
    return order


def tokenize(
    graph: networkx.DiGraph[Block],
    entry: Block,
    *,
    kb: KnowledgeBase | None = None,
    loader=None,
    max_depth: int = 5,
    keep_vvar_category: bool = True,
    keep_sizes: bool = True,
    const_mode: str = "abstract",
    skip_labels: bool = False,
    skip_phis: bool = False,
    compute_bags: bool = False,
    skip_conversions: bool = False,
    skip_dephi: bool = False,
) -> TokenStream:
    """Linearize ``graph`` from ``entry`` and canonicalize every statement into a token.

    ``skip_dephi`` leaves out the copies SSA destruction adds (tagged ``dephi``): they
    appear after the stage the pattern pass runs at, so a pattern must not depend on them.
    """
    order = linearize(graph, entry)
    block_pos = {(b.addr, b.idx): i for i, b in enumerate(order)}
    canon = AILCanonicalizer(
        max_depth=max_depth,
        keep_vvar_category=keep_vvar_category,
        keep_sizes=keep_sizes,
        const_mode=const_mode,
        kb=kb,
        block_pos=block_pos,
        loader=loader,
        skip_conversions=skip_conversions,
    )

    locs: list[TokenLoc] = []
    shapes: list[str] = []
    bags: list[Counter] = []
    block_span: dict[Address, tuple[int, int]] = {}

    for pos, block in enumerate(order):
        start = len(shapes)
        for stmt_idx, stmt in enumerate(block.statements):
            if skip_labels and isinstance(stmt, st.Label):
                continue
            if skip_phis and isinstance(stmt, st.Assignment) and isinstance(stmt.src, ex.Phi):
                continue
            if skip_dephi and is_dephi_copy(stmt):
                continue
            shapes.append(canon.statement(stmt, pos))
            bags.append(canon.bag(stmt) if compute_bags else Counter())
            locs.append(
                TokenLoc(
                    block_addr=block.addr,
                    block_idx=block.idx,
                    stmt_idx=stmt_idx,
                    block_pos=pos,
                    ins_addr=stmt.tags.get("ins_addr"),
                )
            )
        block_span[block.addr, block.idx] = (start, len(shapes))

    shape_vocab: list[str] = []
    shape_index: dict[str, int] = {}
    shape_ids: list[int] = []
    for s in shapes:
        sid = shape_index.get(s)
        if sid is None:
            sid = shape_index[s] = len(shape_vocab)
            shape_vocab.append(s)
        shape_ids.append(sid)

    klass_vocab: list[str] = []
    klass_index: dict[str, int] = {}
    klass_of_shape: list[int] = []
    for s in shape_vocab:
        k = AILCanonicalizer.klass_of(s)
        kid = klass_index.get(k)
        if kid is None:
            kid = klass_index[k] = len(klass_vocab)
            klass_vocab.append(k)
        klass_of_shape.append(kid)

    klass_ids = [klass_of_shape[sid] for sid in shape_ids]
    klasses = [klass_vocab[kid] for kid in klass_ids]

    return TokenStream(
        blocks=order,
        block_span=block_span,
        locs=locs,
        shapes=shapes,
        klasses=klasses,
        bags=bags,
        shape_ids=shape_ids,
        klass_ids=klass_ids,
        shape_vocab=shape_vocab,
        klass_vocab=klass_vocab,
        kb=kb,
        klass_of_shape=klass_of_shape,
    )

from __future__ import annotations

from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Convert,
    Expression,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)
from angr.utils.ail import BlockDefs

from .base import PeepholeOptimizationExprBase


class _LinearForms:
    """
    Expressions as sums ``sum(coef * atom) + const`` modulo 2**bits, expanding virtual variables through their
    graph-wide (pure, location-independent) definitions when those are sums too. An atom is a pure non-sum expression,
    keyed by its structure; anything else gets a key of its own and never cancels.
    """

    def __init__(self, defs, bits: int):
        self.defs = defs
        self.bits = bits
        self.mask = (1 << bits) - 1
        self._memo: dict[int, tuple[dict, int]] = {}
        self._visiting: set[int] = set()
        self.atoms: dict[tuple, Expression] = {}
        # a variable's only definition still depends on where it is evaluated (a load forwarding may resolve later)
        self.pending = False

    def form(self, expr: Expression) -> tuple[dict, int]:
        terms: dict = {}
        const = 0

        def add(e: Expression, sign: int) -> None:
            nonlocal const
            if isinstance(e, BinaryOp) and e.op in {"Add", "Sub"} and not e.floating_point and e.bits == self.bits:
                add(e.operands[0], sign)
                add(e.operands[1], sign if e.op == "Add" else -sign)
            elif isinstance(e, Const) and isinstance(e.value, int):
                const += sign * e.value
            elif isinstance(e, VirtualVariable) and e.bits == self.bits and e.varid not in self._visiting:
                sub_terms, sub_const = self._vvar(e)
                for key, coef in sub_terms.items():
                    terms[key] = terms.get(key, 0) + sign * coef
                const += sign * sub_const
            else:
                key = self._key(e)
                self.atoms.setdefault(key, e)
                terms[key] = terms.get(key, 0) + sign

        add(expr, 1)
        return {k: c & self.mask for k, c in terms.items() if c & self.mask}, const & self.mask

    def _vvar(self, vvar: VirtualVariable) -> tuple[dict, int]:
        memo = self._memo.get(vvar.varid)
        if memo is not None:
            return memo
        # a stack slot's single SSA definition is only as good as the call modelling around its address; do not
        # build on it (a callee writing through the slot's address would make the expansion stale)
        src = None if vvar.was_stack else self.defs.get(vvar.varid)
        if isinstance(src, (BinaryOp, VirtualVariable)) and src.bits == self.bits and (
            isinstance(src, VirtualVariable) or (src.op in {"Add", "Sub"} and not src.floating_point)
        ):
            # SSA definitions do not depend on themselves; the guard only stops a malformed graph
            self._visiting.add(vvar.varid)
            try:
                result = self.form(src)
            finally:
                self._visiting.discard(vvar.varid)
        else:
            if src is None and getattr(self.defs, "definition", None) is not None and self.defs.definition(vvar.varid):
                self.pending = True
            key = ("v", vvar.varid)
            self.atoms.setdefault(key, vvar)
            result = ({key: 1}, 0)
        self._memo[vvar.varid] = result
        return result

    def _key(self, expr: Expression) -> tuple:
        key = _structure(expr)
        return key if key is not None else ("id", id(expr))


def _structure(expr: Expression) -> tuple | None:
    """A structural key of a pure expression (constants, virtual variables, stack offsets and operations on them)."""
    if isinstance(expr, VirtualVariable):
        return ("v", expr.varid)
    if isinstance(expr, Const):
        return ("c", expr.value, expr.bits)
    if isinstance(expr, StackBaseOffset):
        return ("s", expr.offset, expr.bits)
    if isinstance(expr, BinaryOp):
        ops = tuple(_structure(op) for op in expr.operands)
        if None in ops:
            return None
        return ("b", expr.op, expr.bits, expr.signed, expr.floating_point, *ops)
    if isinstance(expr, UnaryOp):
        op = _structure(expr.operand)
        if op is None:
            return None
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
            return ("r", expr.operand.varid, expr.bits)
        return ("u", expr.op, expr.bits, op)
    if isinstance(expr, Convert):
        op = _structure(expr.operand)
        return None if op is None else ("x", expr.from_bits, expr.to_bits, expr.is_signed, op)
    if isinstance(expr, ITE):
        ops = (_structure(expr.cond), _structure(expr.iftrue), _structure(expr.iffalse))
        return None if None in ops else ("i", expr.bits, *ops)
    return None


class AffineVVarCancel(PeepholeOptimizationExprBase):
    """
    ``x + v - w + c`` ==> ``x + c'`` when the graph-wide definitions of ``v`` and ``w`` are sums whose terms cancel
    (``v = w + k``, ``v = u + E`` and ``w = E``, copies), modulo 2**bits. A devirtualized VM spells its rolling key
    through several such variables, so an address computed as ``frame + key - key'`` otherwise never reads as a frame
    slot, and the key stays alive. Rewritten only when something cancels and every surviving term is one of the
    original terms or a virtual variable with coefficient 1 or -1.
    """

    __slots__ = ()

    NAME = "Cancel variables whose definitions differ by a constant"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, block_defs: BlockDefs | None = None, **kwargs):
        if expr.op not in {"Add", "Sub"} or expr.floating_point or block_defs is None or block_defs.all_defs is None:
            return None
        bits = expr.bits
        forms = _LinearForms(block_defs.all_defs, bits)
        # the top-level terms as written
        top: list[tuple[int, Expression]] = []

        def flatten(e: Expression, sign: int) -> None:
            if isinstance(e, BinaryOp) and e.op in {"Add", "Sub"} and not e.floating_point and e.bits == bits:
                flatten(e.operands[0], sign)
                flatten(e.operands[1], sign if e.op == "Add" else -sign)
            elif not (isinstance(e, Const) and isinstance(e.value, int)):
                top.append((sign, e))

        flatten(expr, 1)
        if len(top) < 2:
            return None
        terms, const = forms.form(expr)
        if forms.pending:
            # the statement may cancel once that definition no longer reads memory
            self.fixpoint_reached = False
        if len(terms) >= len(top):
            return None
        mask = forms.mask
        written = {forms._key(t) for _, t in top}
        kept: list[tuple[int, Expression]] = []
        for key, coef in terms.items():
            if coef not in (1, mask):
                return None
            atom = forms.atoms[key]
            if key not in written and not isinstance(atom, VirtualVariable):
                return None
            kept.append((1 if coef == 1 else -1, atom))
        # a positive term first, so that no negation is needed; otherwise the written order
        order = {key: idx for idx, key in enumerate(forms._key(t) for _, t in top)}
        kept.sort(key=lambda t: (t[0] < 0, order.get(forms._key(t[1]), len(order))))
        tags = expr.tags
        result = None
        if kept and kept[0][0] < 0:
            result = Const(self.manager.next_atom(), 0, bits, **tags)
        for sign, term in kept:
            if result is None:
                result = term
            else:
                result = BinaryOp(
                    self.manager.next_atom(), "Add" if sign > 0 else "Sub", [result, term], False, bits=bits, **tags
                )
        if result is None:
            return Const(expr.idx, const, bits, **tags)
        if const:
            op, value = ("Sub", (-const) & mask) if const >> (bits - 1) else ("Add", const)
            result = BinaryOp(
                self.manager.next_atom(),
                op,
                [result, Const(self.manager.next_atom(), value, bits)],
                False,
                bits=bits,
                **tags,
            )
        return result

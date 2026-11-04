"""
Exact canonical forms of integer expressions, to see a devirtualized VM's rolling-key terms cancel.

Themida spells a stack pointer as ``(&frame ^ (k - c)) ^ ((k' + t) - c)``, where ``k`` and ``k' + t`` are one value
computed through different chains of virtual variables. Each chain is irredundant on its own; the equality only shows
once both are expanded down to shared inputs. A canonical form makes it syntactic. Every rule is an identity of
modular integer arithmetic, so two expressions with the same form have the same value:

- a sum is a map from atoms to coefficients modulo 2**bits plus a constant (Add, Sub, Neg, Mul and Shl by a constant,
  BitwiseNeg as ``-x - 1``, truncation of a sum as the sum of the truncations);
- an Xor chain is the set of its terms of odd multiplicity plus a constant; And and Or chains are sets of terms plus
  a constant (both are associative, commutative and idempotent);
- any other operation, and lane-wise (vector) arithmetic, is an atom over the forms of its operands;
- a virtual variable is the form of its single definition (SSA), except for phis, stack slots (whose single SSA
  definition is only as good as the modelling of calls that receive the slot's address) and definitions with side
  effects, which are atoms of their own;
- a stack address is the stack base plus its offset;
- a load is an atom of its address's form and of where it is evaluated: the definition it occurs in, or the statement.
  Loads at one place without a call in between read the same memory. A load from a constant address is instead an
  atom of the address and the block's memory version there: loads of the same bytes in one block read the same value
  unless a store to those bytes, a store through a pointer that is not a stack address, or a call comes between them.
  Anything not understood is a fresh atom.

Forms are interned, so comparing them is comparing integers, and every definition is expanded once.
"""

from __future__ import annotations

import itertools
from bisect import bisect_left

import networkx

from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Convert,
    Expression,
    Extract,
    Insert,
    Load,
    Phi,
    Register,
    StackBaseOffset,
    Call,
    Tmp,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import CAS, Assignment, DirtyStatement, Store

from .block_walkers import PURE_INTRINSIC_CALLS


class _Effects(AILBlockViewer):
    """Virtual variables an expression uses, and whether it has side effects (calls, dirty helpers)."""

    def __init__(self):
        super().__init__()
        self.vvars: list[int] = []
        self.effects = False

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.vvars.append(expr.varid)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if not (isinstance(expr.target, str) and expr.target in PURE_INTRINSIC_CALLS):
            self.effects = True
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self.effects = True

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):
        self.effects = True

    def _handle_MultiStatementExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self.effects = True


def _scan(expr: Expression) -> _Effects:
    viewer = _Effects()
    viewer.walk_expression(expr)
    return viewer


_LIN = "lin"


class _VVarRef:
    __slots__ = ("varid",)

    def __init__(self, varid: int):
        self.varid = varid


def _stack_like(expr: Expression) -> bool:
    """A stack address plus or minus constants: it cannot point into a loaded image."""
    if isinstance(expr, StackBaseOffset):
        return True
    if isinstance(expr, UnaryOp) and expr.op == "Reference":
        return isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack
    if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"}:
        left, right = expr.operands
        if isinstance(right, Const):
            return _stack_like(left)
        return expr.op == "Add" and isinstance(left, Const) and _stack_like(right)
    return False


class _MemoryVersions:
    """
    Per block, the writes before each statement: two loads of the same constant bytes at points with the same version
    read the same value.
    """

    def __init__(self, graph: networkx.DiGraph):
        # block key -> (indices of statements that may write anything, constant-address stores (idx, lo, hi))
        self._events: dict[tuple, tuple[list[int], list[tuple[int, int, int]]]] = {}
        for block in graph:
            unknown: list[int] = []
            stores: list[tuple[int, int, int]] = []
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, (CAS, DirtyStatement)) or _StmtEffects.of(stmt):
                    unknown.append(idx)
                elif isinstance(stmt, Store):
                    if isinstance(stmt.addr, Const) and isinstance(stmt.addr.value, int):
                        stores.append((idx, stmt.addr.value, stmt.addr.value + stmt.size))
                    elif not _stack_like(stmt.addr):
                        unknown.append(idx)
            self._events[(block.addr, block.idx)] = (unknown, stores)

    def version(self, loc: tuple, lo: int, hi: int) -> tuple | None:
        block_key, idx = loc
        events = self._events.get(block_key)
        if events is None:
            return None
        unknown, stores = events
        last = max((i for i, a, b in stores if i < idx and a < hi and lo < b), default=-1)
        return block_key, bisect_left(unknown, idx), last


class CanonicalForms:
    """
    Interned canonical forms over the definitions of an AIL graph. ``form(expr, site)`` is an integer; equal integers
    mean equal values wherever both expressions are evaluated at their sites.
    """

    def __init__(self, graph: networkx.DiGraph):
        self._defs: dict[int, Expression] = {}
        self._def_locs: dict[int, tuple] = {}
        seen: set[int] = set()
        for block in graph:
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    varid = stmt.dst.varid
                    if varid in seen:
                        self._defs.pop(varid, None)
                        continue
                    seen.add(varid)
                    if not isinstance(stmt.src, Phi) and not stmt.dst.was_stack and stmt.src.bits == stmt.dst.bits:
                        self._defs[varid] = stmt.src
                        self._def_locs[varid] = ((block.addr, block.idx), idx)
        self._memory = _MemoryVersions(graph)
        self._ids: dict[tuple, int] = {}
        self._keys: list[tuple] = []
        self._vvar_forms: dict[int, int] = {}
        self._fresh = itertools.count()
        self._forming: set[int] = set()
        # (id(expr), site key) -> (expr, form); holding expr keeps its id from being reused
        self._memo: dict[tuple, tuple[Expression, int]] = {}
        # atom id of a load whose address is not constant -> that load
        self.loads: dict[int, Load] = {}
        # atom id of a load from a constant address -> the variables defined as exactly that load, with their location
        self.cload_holders: dict[int, list[tuple[int, tuple]]] = {}
        # ... -> (variable, location, load) of definitions the load is part of
        self.cload_sites: dict[int, list[tuple[int, tuple, Load]]] = {}

    #
    # interning
    #

    def _intern(self, key: tuple) -> int:
        fid = self._ids.get(key)
        if fid is None:
            fid = len(self._keys)
            self._ids[key] = fid
            self._keys.append(key)
        return fid

    def key(self, fid: int) -> tuple:
        return self._keys[fid]

    def _lin(self, bits: int, terms: dict[int, int], const: int) -> int:
        mask = (1 << bits) - 1
        items = tuple(sorted((a, c & mask) for a, c in terms.items() if c & mask))
        return self._intern((_LIN, bits, items, const & mask))

    def _atom(self, bits: int, key: tuple) -> int:
        return self._lin(bits, {self._intern(key): 1}, 0)

    def _fresh_atom(self, bits: int) -> int:
        return self._atom(bits, ("fresh", next(self._fresh)))

    def _parts(self, fid: int) -> tuple[int, dict[int, int], int]:
        _, bits, items, const = self._keys[fid]
        return bits, dict(items), const

    def const_of(self, fid: int) -> int | None:
        _, _, items, const = self._keys[fid]
        return None if items else const

    def single_atom(self, fid: int) -> tuple[tuple, int] | None:
        """(atom key, constant) if the form is ``atom + constant``."""
        _, _, items, const = self._keys[fid]
        if len(items) == 1 and items[0][1] == 1:
            return self._keys[items[0][0]], const
        return None

    def _unwrap(self, fid: int, kind: str) -> tuple | None:
        """The atom key if the form is exactly one atom of this kind."""
        _, _, items, const = self._keys[fid]
        if const == 0 and len(items) == 1 and items[0][1] == 1:
            atom = self._keys[items[0][0]]
            if atom[0] == kind:
                return atom
        return None

    #
    # definitions
    #

    def _prepare(self, expr) -> None:
        """Form every definition ``expr`` depends on, innermost first, so that forming ``expr`` only recurses into
        expression trees."""
        stack = [(expr.varid, False)] if isinstance(expr, _VVarRef) else [(v, False) for v in _scan(expr).vvars]
        visiting: set[int] = set()
        while stack:
            varid, done = stack.pop()
            if varid in self._vvar_forms:
                continue
            src = self._defs.get(varid)
            if done:
                visiting.discard(varid)
                self._vvar_forms[varid] = self._form_def(varid, src)
                continue
            if src is None or varid in visiting:
                # no usable definition, or a malformed cycle
                continue
            scan = _scan(src)
            if scan.effects:
                self._defs.pop(varid)
                continue
            visiting.add(varid)
            stack.append((varid, True))
            stack.extend((v, False) for v in scan.vvars if v not in self._vvar_forms)

    def _form_def(self, varid: int, src: Expression) -> int:
        site = (("def", varid), self._def_locs[varid])
        if isinstance(src, Load):
            fid = self._const_load(src, site)
            if fid is None:
                # the variable names the loaded value
                return self._atom(src.bits, ("v", varid))
            self.cload_holders.setdefault(self._keys[fid][2][0][0], []).append((varid, site[1]))
            return fid
        self._forming.add(varid)
        try:
            return self._form(src, site)
        finally:
            self._forming.discard(varid)

    def _const_load(self, load: Load, site) -> int | None:
        """The form of a load from a constant address, by the block's memory version at the site."""
        if not (isinstance(load.addr, Const) and isinstance(load.addr.value, int)) or site is None:
            return None
        lo = load.addr.value
        version = self._memory.version(site[1], lo, lo + load.size)
        if version is None:
            return None
        return self._atom(load.bits, ("cload", version, lo, load.size, load.endness))

    def _vvar(self, expr: VirtualVariable) -> int:
        fid = self._vvar_forms.get(expr.varid)
        if fid is not None:
            return fid
        if expr.varid in self._defs and expr.varid not in self._forming:
            self._prepare(expr)
            fid = self._vvar_forms.get(expr.varid)
            if fid is not None:
                return fid
        fid = self._atom(expr.bits, ("v", expr.varid))
        self._vvar_forms[expr.varid] = fid
        return fid

    #
    # forms
    #

    def form(self, expr: Expression, site=None) -> int:
        """
        :param site: Where ``expr`` is evaluated, for telling loads apart: (a key for the place, ((block addr, block
                     idx), statement idx)). None makes every load in it an atom of its own; the caller passes None
                     where a call may run between the loads.
        """
        self._prepare(expr)
        if site is not None and _scan(expr).effects:
            site = None
        return self._form(expr, site)

    def prepare_statement(self, stmt) -> bool:
        """Form the definitions a statement depends on. Returns whether it has side effects (see ``form_at``)."""
        viewer = _StmtEffects()
        viewer.walk_statement(stmt)
        for varid in viewer.vvars:
            if varid not in self._vvar_forms and varid in self._defs:
                self._prepare(_VVarRef(varid))
        return viewer.effects

    def form_at(self, expr: Expression, site) -> int:
        """``form`` for a part of a statement that ``prepare_statement`` has seen; ``site`` must be None if the
        statement has side effects."""
        return self._form(expr, site)

    def _form(self, expr: Expression, site) -> int:
        key = (id(expr), None if site is None else site[0])
        hit = self._memo.get(key)
        if hit is not None and hit[0] is expr:
            return hit[1]
        fid = self._form_uncached(expr, site)
        if site is not None:
            self._memo[key] = (expr, fid)
        return fid

    def _form_uncached(self, expr: Expression, site) -> int:
        bits = expr.bits
        if isinstance(expr, Const):
            if isinstance(expr.value, int):
                return self._lin(bits, {}, expr.value)
            return self._atom(bits, ("fconst", repr(expr.value), bits))
        if isinstance(expr, VirtualVariable):
            fid = self._vvar(expr)
            if self._keys[fid][1] != bits:
                return self._atom(bits, ("v", expr.varid))
            return fid
        if isinstance(expr, StackBaseOffset):
            return self._lin(bits, {self._intern(("sb", bits)): 1}, expr.offset)
        if isinstance(expr, UnaryOp):
            return self._unary(expr, site)
        if isinstance(expr, BinaryOp):
            return self._binary(expr, site)
        if isinstance(expr, Convert):
            return self._convert(expr, site)
        if isinstance(expr, Load):
            if site is None:
                return self._fresh_atom(bits)
            fid = self._const_load(expr, site)
            if fid is not None:
                if site[0][0] == "def":
                    self.cload_sites.setdefault(self._keys[fid][2][0][0], []).append((site[0][1], site[1], expr))
                return fid
            addr = self._form(expr.addr, site)
            fid = self._atom(bits, ("load", site[0], addr, expr.size, expr.endness))
            self.loads.setdefault(self._keys[fid][2][0][0], expr)
            return fid
        if isinstance(expr, Tmp):
            return self._fresh_atom(bits) if site is None else self._atom(bits, ("tmp", site[0], expr.tmp_idx))
        if isinstance(expr, Register):
            return self._fresh_atom(bits) if site is None else self._atom(bits, ("reg", site[0], expr.reg_offset))
        if isinstance(expr, ITE):
            ops = tuple(self._form(op, site) for op in (expr.cond, expr.iftrue, expr.iffalse))
            return self._atom(bits, ("ite", bits, ops))
        if isinstance(expr, Insert):
            ops = tuple(self._form(op, site) for op in (expr.base, expr.offset, expr.value))
            return self._atom(bits, ("insert", bits, expr.endness, ops))
        if isinstance(expr, Extract):
            ops = tuple(self._form(op, site) for op in (expr.base, expr.offset))
            return self._atom(bits, ("extract", bits, expr.endness, ops))
        if isinstance(expr, VEXCCallExpression):
            ops = tuple(self._form(op, site) for op in expr.operands)
            return self._atom(bits, ("ccall", expr.callee, bits, ops))
        return self._fresh_atom(bits)

    def sb_coefficient(self, fid: int) -> int:
        """The coefficient of the stack base in a form (0 if none)."""
        _, bits, items, _ = self._keys[fid]
        sb = self._ids.get(("sb", bits))
        return next((c for a, c in items if a == sb), 0)

    def stack_witness(self, expr: Expression, site) -> tuple[Expression, int] | None:
        """
        A stack address expression, and its offset, that ``expr`` (whose form has the stack base with coefficient 1)
        gets its stack base from: followed down operands and definitions that carry the stack base with coefficient 1.
        """
        bits = expr.bits
        while True:
            if isinstance(expr, StackBaseOffset):
                return expr, expr.offset
            if isinstance(expr, UnaryOp) and expr.op == "Reference":
                operand = expr.operand
                if isinstance(operand, VirtualVariable) and operand.was_stack:
                    return expr, operand.stack_offset
                return None
            if isinstance(expr, VirtualVariable):
                src = self._defs.get(expr.varid)
                if src is None or isinstance(src, Load) or self._vvar_forms.get(expr.varid) is None:
                    return None
                expr, site = src, (("def", expr.varid), self._def_locs[expr.varid])
                continue
            if isinstance(expr, Convert) and expr.from_bits == expr.to_bits:
                expr = expr.operand
                continue
            if isinstance(expr, BinaryOp) and expr.op == "Xor" and not expr.vector_count:
                # the one term of the flattened chain that survives (odd multiplicity) and carries the stack base
                leaves = self._xor_leaves(expr, site)
                counts: dict[int, int] = {}
                for _, _, fid in leaves:
                    counts[fid] = counts.get(fid, 0) + 1
                nxt = next(
                    ((e, s) for e, s, fid in leaves if counts[fid] % 2 and self.sb_coefficient(fid) == 1), None
                )
                if nxt is None:
                    return None
                expr, site = nxt
                continue
            if isinstance(expr, BinaryOp) and expr.op in {"Add", "Sub"} and not expr.vector_count:
                nxt = None
                for i, operand in enumerate(expr.operands):
                    if operand.bits != bits or (expr.op == "Sub" and i == 1):
                        continue
                    if self.sb_coefficient(self._form(operand, site)) == 1:
                        nxt = operand
                        break
                if nxt is None:
                    return None
                expr = nxt
                continue
            return None

    def _xor_leaves(self, expr: Expression, site) -> list[tuple[Expression, object, int]]:
        """The terms of an Xor chain, through nested Xors and variables defined as one, with their sites and forms."""
        bits = expr.bits
        out = []
        stack = [(expr, site)]
        while stack:
            e, s = stack.pop()
            if isinstance(e, BinaryOp) and e.op == "Xor" and e.bits == bits and not e.vector_count:
                stack.extend((o, s) for o in reversed(e.operands))
                continue
            if isinstance(e, VirtualVariable) and e.varid in self._vvar_forms:
                src = self._defs.get(e.varid)
                if isinstance(src, BinaryOp) and src.op == "Xor" and src.bits == bits and not src.vector_count:
                    stack.append((src, (("def", e.varid), self._def_locs[e.varid])))
                    continue
            out.append((e, s, self._form(e, s)))
        return out

    def _unary(self, expr: UnaryOp, site) -> int:
        bits = expr.bits
        if expr.op == "Reference":
            operand = expr.operand
            if isinstance(operand, VirtualVariable) and operand.was_stack:
                return self._lin(bits, {self._intern(("sb", bits)): 1}, operand.stack_offset)
            if isinstance(operand, VirtualVariable):
                return self._atom(bits, ("ref", operand.varid, bits))
            return self._fresh_atom(bits)
        inner = self._form(expr.operand, site)
        if self._keys[inner][1] == bits and expr.op in {"Neg", "BitwiseNeg"}:
            _, terms, const = self._parts(inner)
            mask = (1 << bits) - 1
            terms = {a: -c for a, c in terms.items()}
            # ~x == -x - 1
            return self._lin(bits, terms, -const if expr.op == "Neg" else -const - 1 & mask)
        return self._atom(bits, ("u", expr.op, bits, inner))

    def _convert(self, expr: Convert, site) -> int:
        inner = self._form(expr.operand, site)
        lanes = expr.vector_count
        if lanes and lanes > 1:
            return self._atom(expr.bits, ("vconv", lanes, expr.from_bits, expr.to_bits, expr.is_signed, inner))
        if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
            return self._atom(expr.bits, ("conv", expr.from_type, expr.to_type, expr.from_bits, expr.to_bits, inner))
        if expr.to_bits == expr.from_bits:
            return inner
        if expr.to_bits < expr.from_bits and self._keys[inner][1] == expr.from_bits:
            # truncation is a ring homomorphism: truncate each atom
            to = expr.to_bits
            _, terms, const = self._parts(inner)
            new_terms: dict[int, int] = {}
            for atom, coef in terms.items():
                akey = self._keys[atom]
                if akey[0] == "sb":
                    sub = self._intern(("sb", to))
                else:
                    sub = self._intern(("trunc", to, self._lin(expr.from_bits, {atom: 1}, 0)))
                new_terms[sub] = new_terms.get(sub, 0) + coef
            return self._lin(to, new_terms, const)
        return self._atom(expr.bits, ("ext", expr.from_bits, expr.to_bits, expr.is_signed, inner))

    def _binary(self, expr: BinaryOp, site) -> int:
        bits = expr.bits
        op = expr.op
        left = self._form(expr.operands[0], site)
        right = self._form(expr.operands[1], site)
        same_width = self._keys[left][1] == bits and self._keys[right][1] == bits
        lanes = expr.vector_count
        if lanes and lanes > 1 and op not in {"Xor", "And", "Or"}:
            # lane-wise arithmetic does not carry across lanes; bitwise operations are the same either way
            return self._atom(bits, ("vop", op, bits, lanes, expr.vector_size, expr.signed, (left, right)))
        if expr.floating_point or op.startswith("Cmp") or not same_width:
            if op in {"Shl", "Shr", "Sar"} and self._keys[left][1] == bits and not expr.floating_point:
                amount = self.const_of(right)
                if op == "Shl" and amount is not None and amount < bits:
                    _, terms, const = self._parts(left)
                    return self._lin(bits, {a: c << amount for a, c in terms.items()}, const << amount)
            return self._atom(bits, ("op", op, bits, expr.signed, expr.floating_point, (left, right)))
        if op in {"Add", "Sub"}:
            _, lt, lc = self._parts(left)
            _, rt, rc = self._parts(right)
            sign = 1 if op == "Add" else -1
            for a, c in rt.items():
                lt[a] = lt.get(a, 0) + sign * c
            return self._lin(bits, lt, lc + sign * rc)
        if op == "Mul":
            for scaled, factor in ((left, right), (right, left)):
                k = self.const_of(factor)
                if k is not None:
                    _, terms, const = self._parts(scaled)
                    return self._lin(bits, {a: c * k for a, c in terms.items()}, const * k)
            return self._atom(bits, ("op", op, bits, False, False, tuple(sorted((left, right)))))
        if op in {"Shl", "Shr", "Sar"}:
            amount = self.const_of(right)
            if op == "Shl" and amount is not None and amount < bits:
                _, terms, const = self._parts(left)
                return self._lin(bits, {a: c << amount for a, c in terms.items()}, const << amount)
            return self._atom(bits, ("op", op, bits, expr.signed, False, (left, right)))
        if op == "Xor":
            return self._xor(bits, (left, right))
        if op in {"And", "Or"}:
            return self._and_or(op, bits, (left, right))
        return self._atom(bits, ("op", op, bits, expr.signed, False, (left, right)))

    def _xor(self, bits: int, operands) -> int:
        odd: set[int] = set()
        const = 0
        for fid in operands:
            c = self.const_of(fid)
            if c is not None:
                const ^= c
                continue
            nested = self._unwrap(fid, "xor")
            members = (nested[2], nested[3]) if nested is not None and nested[1] == bits else ((fid,), 0)
            for member in members[0]:
                odd ^= {member}
            const ^= members[1]
        if not odd:
            return self._lin(bits, {}, const)
        if len(odd) == 1 and not const:
            return next(iter(odd))
        return self._atom(bits, ("xor", bits, tuple(sorted(odd)), const))

    def _and_or(self, op: str, bits: int, operands) -> int:
        mask = (1 << bits) - 1
        kind = op.lower()
        members: set[int] = set()
        const = mask if op == "And" else 0
        for fid in operands:
            c = self.const_of(fid)
            if c is not None:
                const = const & c if op == "And" else const | c
                continue
            nested = self._unwrap(fid, kind)
            if nested is not None and nested[1] == bits:
                members.update(nested[2])
                const = const & nested[3] if op == "And" else const | nested[3]
            else:
                members.add(fid)
        absorbing = 0 if op == "And" else mask
        identity = mask if op == "And" else 0
        if const == absorbing or not members:
            return self._lin(bits, {}, const)
        if len(members) == 1 and const == identity:
            return next(iter(members))
        return self._atom(bits, (kind, bits, tuple(sorted(members)), const))


class _Subexpressions(AILBlockViewer):
    """
    Every expression of a statement, outermost first, where the subtree of each ends in that order, the positions
    whose subtree has side effects (a call, a dirty helper), and the positions inside condition-code helper operands.
    """

    def __init__(self):
        super().__init__()
        self.exprs: list[Expression] = []
        self.ends: list[int] = []
        self.effects: set[int] = set()
        self.in_ccall: set[int] = set()
        self._open: list[int] = []
        self._ccall_depth = 0

    def _handle_VEXCCallExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self._ccall_depth += 1
        try:
            super()._handle_VEXCCallExpression(expr_idx, expr, stmt_idx, stmt, block)
        finally:
            self._ccall_depth -= 1

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        pos = len(self.exprs)
        self.exprs.append(expr)
        self.ends.append(pos + 1)
        if self._ccall_depth:
            self.in_ccall.add(pos)
        self._open.append(pos)
        try:
            return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        finally:
            self._open.pop()
            self.ends[pos] = len(self.exprs)

    def _effect(self) -> None:
        self.effects.update(self._open)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if not (isinstance(expr.target, str) and expr.target in PURE_INTRINSIC_CALLS):
            self._effect()
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self._effect()
        super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):
        self._effect()
        super()._handle_FunctionLikeMacro(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_MultiStatementExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        self._effect()
        super()._handle_MultiStatementExpression(expr_idx, expr, stmt_idx, stmt, block)


class _VVars(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.vvars: list[VirtualVariable] = []

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.vvars.append(expr)

    @staticmethod
    def of(expr: Expression) -> list[VirtualVariable]:
        viewer = _VVars()
        viewer.walk_expression(expr)
        return viewer.vvars


class _StackRefs(AILBlockViewer):
    """The stack address expressions of one width in an expression, by offset."""

    def __init__(self, bits: int):
        super().__init__()
        self.bits = bits
        self.refs: dict[int, Expression] = {}

    def _handle_StackBaseOffset(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.bits == self.bits:
            self.refs.setdefault(expr.offset, expr)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        operand = expr.operand
        if expr.op == "Reference" and isinstance(operand, VirtualVariable) and operand.was_stack:
            if expr.bits == self.bits:
                self.refs.setdefault(operand.stack_offset, expr)
            return
        super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    @staticmethod
    def of(expr: Expression, bits: int) -> dict[int, Expression]:
        viewer = _StackRefs(bits)
        viewer.walk_expression(expr)
        return viewer.refs


class _StmtEffects(_Effects):
    @staticmethod
    def of(stmt) -> bool:
        viewer = _StmtEffects()
        viewer.walk_statement(stmt)
        return viewer.effects


def _contains(stmt, expr: Expression) -> bool:
    walker = _Subexpressions()
    walker.walk_statement(stmt)
    return any(e.likes(expr) for e in walker.exprs)


def _is_compound(expr: Expression) -> bool:
    """
    Whether an expression is more than one leaf (variable, stack address, load) plus or minus constants. Nothing else
    can cancel; respelling a load as an earlier one of the same bytes would only move the VM context's loads around.
    """
    leaves = 0
    stack = [expr]
    while stack:
        e = stack.pop()
        if isinstance(e, BinaryOp) and e.op in {"Add", "Sub"}:
            stack.extend(e.operands)
        elif isinstance(e, Const):
            continue
        elif isinstance(e, (VirtualVariable, StackBaseOffset, Load)) or (isinstance(e, UnaryOp) and e.op == "Reference"):
            leaves += 1
        else:
            return True
    return leaves > 1


class CanonicalFormResolver:
    """
    Rewrite each compound expression whose canonical form is a constant, a stack address, or one value plus a constant
    to that spelling, outermost first. The value may be

    - a temporary virtual variable, or a variable the expression spells (whose definition, in SSA, dominates the use);
    - a variable of the same block defined earlier as a load of the same constant bytes at the same memory version;
    - a load: the load itself if it is part of the same statement, else a new temporary that names it right before
      the definition it is part of (which dominates every use of the variable it defines). Not in a block with
      specialized copies, which must stay alike.

    A stack address is spelled only from a stack address the expression itself contains or computes it from (see
    ``CanonicalForms.stack_witness``), never anew. Temporaries only: leaving SSA merges register and stack variables with
    later definitions of the same register or slot.
    """

    def __init__(self, graph: networkx.DiGraph, pointer_bits: int, ail_manager=None, new_vvar_id=None):
        self._graph = graph
        self._pointer_bits = pointer_bits
        self._manager = ail_manager
        self._new_vvar_id = new_vvar_id
        self.resolved = 0
        self.named = 0

    def _next_atom(self) -> int | None:
        return self._manager.next_atom() if self._manager is not None else None

    def _const(self, value: int, bits: int, tags) -> Const:
        return Const(self._next_atom(), value & ((1 << bits) - 1), bits, **tags)

    def _plus(self, base: Expression, offset: int, bits: int, tags) -> Expression:
        mask = (1 << bits) - 1
        offset &= mask
        if not offset:
            return base
        if offset >> (bits - 1):
            return BinaryOp(self._next_atom(), "Sub", [base, self._const(-offset, bits, {})], False, bits=bits, **tags)
        return BinaryOp(self._next_atom(), "Add", [base, self._const(offset, bits, {})], False, bits=bits, **tags)

    def _simpler(self, forms: CanonicalForms, expr: Expression, site, loc, vvars, nameable):
        """A simpler spelling of ``expr`` at ``loc``: an expression, or ("name", definition varid, load, offset)."""
        fid = forms.form_at(expr, site)
        bits = expr.bits
        tags = dict(expr.tags)
        const = forms.const_of(fid)
        if const is not None:
            return self._const(const, bits, tags)
        single = forms.single_atom(fid)
        if single is None:
            return None
        atom, offset = single
        mask = (1 << bits) - 1
        if atom[0] == "sb":
            if bits != self._pointer_bits:
                # the low bits of a stack address are not an address
                return None
            signed = offset - (1 << bits) if offset >> (bits - 1) else offset
            # spelled from the stack address the program computes it from: stack SSA attributes an access to a stack
            # object by how its address is spelled (and a Reference names one SSA version of the slot), so another
            # spelling of bytes the program also reaches this way could make the two disagree
            local = _StackRefs.of(expr, bits)
            if signed in local:
                return local[signed]
            witness = forms.stack_witness(expr, site)
            if witness is None:
                return None
            base, base_offset = witness
            return self._plus(base, (signed - base_offset) & mask, bits, tags)
        if atom[0] == "v":
            vvar = vvars.get(atom[1])
            if vvar is None:
                # a variable the expression spells whose value is that atom (a copy of it, say)
                target = forms._atom(bits, atom)
                vvar = next(
                    (v for v in _VVars.of(expr) if v.bits == bits and forms.form_at(v, site) == target), None
                )
            if vvar is None or vvar.bits != bits:
                return None
            return self._plus(vvar, offset, bits, tags)
        if atom[0] == "cload":
            atom_id = forms._intern(atom)
            # a variable of the block defined as that load before this statement holds the value
            for varid, (block_key, idx) in forms.cload_holders.get(atom_id, ()):
                if block_key == loc[0] and idx < loc[1] and varid in vvars:
                    return self._plus(vvars[varid], offset, bits, tags)
            # or the load is part of such a definition, and gets a name in front of it (same memory version)
            for varid, (block_key, idx), load in forms.cload_sites.get(atom_id, ()):
                if block_key == loc[0] and idx < loc[1] and varid in nameable and load.bits == bits:
                    return ("name", varid, load, offset)
            return None
        if atom[0] == "load" and site is not None:
            load = forms.loads.get(forms._intern(atom))
            if load is None or load.bits != bits:
                return None
            if atom[1] == site[0]:
                # a load of this very statement
                return self._plus(load, offset, bits, tags)
            if atom[1][0] == "def" and atom[1][1] in nameable:
                return ("name", atom[1][1], load, offset)
        return None

    def run(self) -> dict:
        """The rewritten blocks, ``{old block: new block}``. The graph is not modified."""
        forms = CanonicalForms(self._graph)
        copies: dict[int, int] = {}
        for block in self._graph:
            copies[block.addr] = copies.get(block.addr, 0) + 1
        # temporaries, which leaving SSA never merges with another definition; definitions a new temporary can be
        # put in front of (a block with specialized copies must stay identical to them)
        vvars: dict[int, VirtualVariable] = {}
        def_at: dict[int, tuple] = {}
        for block in self._graph:
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    if stmt.dst.was_tmp:
                        vvars[stmt.dst.varid] = stmt.dst
                    def_at[stmt.dst.varid] = (block, idx)
        nameable = (
            {v for v, (b, _) in def_at.items() if copies[b.addr] == 1}
            if self._new_vvar_id is not None and self._manager is not None
            else set()
        )

        # (block, stmt idx) -> [(old expression, new expression or naming request)]
        plans: dict[tuple, list] = {}
        for block in self._graph:
            for stmt_idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                    continue
                loc = ((block.addr, block.idx), stmt_idx)
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    site = (("def", stmt.dst.varid), loc)
                else:
                    site = (("stmt", loc), loc)
                if forms.prepare_statement(stmt):
                    # a call may run between two loads of the statement
                    site = None
                walker = _Subexpressions()
                walker.walk_statement(stmt)
                pos = 0
                while pos < len(walker.exprs):
                    sub = walker.exprs[pos]
                    # a call stays, and so does everything that holds one: its effects are not part of the value. The
                    # operands of condition-code helpers stay as written: the flags rewriters match their shapes
                    rewritable = (
                        pos not in walker.effects
                        and pos not in walker.in_ccall
                        and not isinstance(sub, Call)
                        and _is_compound(sub)
                    )
                    new = self._simpler(forms, sub, site, loc, vvars, nameable) if rewritable else None
                    if new is None or (not isinstance(new, tuple) and new.likes(sub)):
                        pos += 1
                        continue
                    plans.setdefault((block, stmt_idx), []).append((sub, new))
                    # the parts of a rewritten expression go with it
                    pos = walker.ends[pos]

        # a definition that gets a load named in front of it is not rewritten itself
        named: dict[tuple, tuple[VirtualVariable, Load]] = {}
        for items in plans.values():
            for i, (sub, new) in enumerate(items):
                if not isinstance(new, tuple):
                    continue
                _, varid, load, offset = new
                def_block, def_idx = def_at[varid]
                if def_at[varid] in plans or not _contains(def_block.statements[def_idx], load):
                    items[i] = (sub, None)
                    continue
                key = (varid, id(load))
                if key not in named:
                    tid = self._new_vvar_id()
                    tmp = VirtualVariable(
                        self._next_atom(), tid, load.bits, VirtualVariableCategory.TMP, oident=tid, **load.tags
                    )
                    named[key] = (tmp, load)
                items[i] = (sub, self._plus(named[key][0], offset, sub.bits, dict(sub.tags)))
        # definition -> [(temporary, load)] to put in front of it
        names: dict[tuple, list] = {}
        for (varid, _), pair in named.items():
            names.setdefault(def_at[varid], []).append(pair)

        replacements = {}
        for block in self._graph:
            stmts = []
            changed = False
            for stmt_idx, stmt in enumerate(block.statements):
                for sub, new in plans.get((block, stmt_idx), ()):
                    if new is None:
                        continue
                    replaced, new_stmt = stmt.replace(sub, new)
                    if replaced and not new_stmt.likes(stmt):
                        stmt = new_stmt
                        self.resolved += 1
                        changed = True
                for tmp, load in names.get((block, stmt_idx), ()):
                    _, new_stmt = stmt.replace(load, tmp)
                    stmts.append(Assignment(self._next_atom(), tmp, load, **stmt.tags))
                    stmt = new_stmt
                    self.named += 1
                    changed = True
                stmts.append(stmt)
            if changed:
                replacements[block] = block.copy(statements=stmts)
        return replacements

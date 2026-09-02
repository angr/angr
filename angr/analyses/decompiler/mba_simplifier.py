from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import claripy

from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Expression,
    Load,
    Register,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)

if TYPE_CHECKING:
    from angr.ailment.manager import Manager

l = logging.getLogger(name=__name__)

#: Operators an MBA expression is built from. Anything else ends the subtree.
_BOOLEAN_BINOPS = frozenset({"And", "Or", "Xor"})
_ARITH_BINOPS = frozenset({"Add", "Sub", "Mul"})
_BOOLEAN_UNOPS = frozenset({"BitwiseNeg", "Not"})
_ARITH_UNOPS = frozenset({"Neg"})

#: Expressions treated as opaque inputs rather than walked into.
_LEAF_TYPES = (VirtualVariable, Register, Load, StackBaseOffset, Convert)

#: A signature is 2**n evaluations, so this bounds the work per candidate.
MAX_VARS = 6
#: Beyond this an expression is unlikely to be a single obfuscated operation.
MAX_NODES = 64


class _Unsupported(Exception):
    """The subtree contains something outside the MBA fragment."""


class MBATemplateSimplifier:
    """
    Recognise mixed boolean-arithmetic expressions and replace them with what they compute.

    An obfuscator rewrites ``x + y`` into a tangle of ``^``, ``&``, ``|`` and ``+`` that is
    equivalent for every input but unreadable. Matching those tangles syntactically does not work
    for long -- the templates are generated and randomised -- so this identifies them by behaviour
    instead:

    1. translate the subtree into claripy over one symbolic variable per distinct leaf;
    2. compare its *signature* -- its value on every assignment of the leaves to all-zeroes and
       all-ones -- against the signature of each candidate template. For a linear MBA every
       bitwise term is constant across bit positions under those inputs, so equal signatures make
       a match very likely and an unequal one rules it out outright;
    3. prove the survivor equivalent with the solver before rewriting anything.

    Step 2 is only a filter. Step 3 is what makes a rewrite safe, and nothing is rewritten without
    it: a plausible-looking MBA identity that is subtly wrong silently changes what the program
    does, which is worse than leaving the expression ugly.
    """

    def __init__(self, ail_manager: Manager | None = None, max_vars: int = MAX_VARS):
        self._ail_manager = ail_manager
        self._max_vars = max_vars
        self.simplified = 0
        self.candidates = 0
        self.verified_away = 0

    #
    # translation
    #

    @staticmethod
    def _is_leaf(expr) -> bool:
        return isinstance(expr, _LEAF_TYPES)

    def _collect(self, expr, leaves: dict[str, Expression], depth: int = 0) -> int:
        """Count the nodes of an MBA subtree and record its leaves, or raise _Unsupported."""
        if depth > 64:
            raise _Unsupported
        if isinstance(expr, Const):
            return 1
        if self._is_leaf(expr):
            leaves.setdefault(str(expr), expr)
            return 1
        if isinstance(expr, BinaryOp):
            if expr.op not in _BOOLEAN_BINOPS and expr.op not in _ARITH_BINOPS:
                raise _Unsupported
            return 1 + sum(self._collect(o, leaves, depth + 1) for o in expr.operands)
        if isinstance(expr, UnaryOp):
            if expr.op not in _BOOLEAN_UNOPS and expr.op not in _ARITH_UNOPS:
                raise _Unsupported
            return 1 + self._collect(expr.operand, leaves, depth + 1)
        raise _Unsupported

    def _to_claripy(self, expr, env: dict[str, claripy.ast.BV], bits: int):
        if isinstance(expr, Const):
            return claripy.BVV(expr.value & ((1 << bits) - 1), bits)
        if self._is_leaf(expr):
            return env[str(expr)]
        if isinstance(expr, BinaryOp):
            a, b = (self._to_claripy(o, env, bits) for o in expr.operands)
            return {
                "And": lambda: a & b,
                "Or": lambda: a | b,
                "Xor": lambda: a ^ b,
                "Add": lambda: a + b,
                "Sub": lambda: a - b,
                "Mul": lambda: a * b,
            }[expr.op]()
        if isinstance(expr, UnaryOp):
            inner = self._to_claripy(expr.operand, env, bits)
            return ~inner if expr.op in _BOOLEAN_UNOPS else -inner
        raise _Unsupported

    #
    # templates
    #

    @staticmethod
    def _templates(names: list[str]):
        """
        Candidate meanings, cheapest first, as (label, builder over the leaf variables).

        Only forms simpler than the tangle they would replace are worth offering; a template that
        is no smaller buys nothing.
        """
        out: list[tuple[str, object]] = []
        if len(names) >= 1:
            out += [
                ("x", lambda v: v[0]),
                ("~x", lambda v: ~v[0]),
                ("-x", lambda v: -v[0]),
            ]
        if len(names) >= 2:
            out += [
                ("x + y", lambda v: v[0] + v[1]),
                ("x - y", lambda v: v[0] - v[1]),
                ("y - x", lambda v: v[1] - v[0]),
                ("x ^ y", lambda v: v[0] ^ v[1]),
                ("x & y", lambda v: v[0] & v[1]),
                ("x | y", lambda v: v[0] | v[1]),
                ("~(x ^ y)", lambda v: ~(v[0] ^ v[1])),
                ("-(x + y)", lambda v: -(v[0] + v[1])),
            ]
        if len(names) >= 3:
            out += [
                ("x + y + z", lambda v: v[0] + v[1] + v[2]),
                ("x ^ y ^ z", lambda v: v[0] ^ v[1] ^ v[2]),
                ("(x ^ y) + z", lambda v: (v[0] ^ v[1]) + v[2]),
                ("(x & y) | z", lambda v: (v[0] & v[1]) | v[2]),
            ]
        return out

    @staticmethod
    def _signature(fn, variables, bits: int) -> tuple[int, ...] | None:
        """Value of ``fn`` at every assignment of the variables to all-zeroes / all-ones."""
        n = len(variables)
        mask = (1 << bits) - 1
        out = []
        for pattern in range(1 << n):
            concrete = [claripy.BVV(mask if (pattern >> i) & 1 else 0, bits) for i in range(n)]
            try:
                value = fn(concrete)
            except Exception:  # pylint:disable=broad-except
                return None
            if value.op != "BVV":
                return None
            out.append(value.args[0])
        return tuple(out)

    #
    # entry point
    #

    def simplify(self, expr: Expression) -> Expression | None:
        """Return a simpler equivalent of an MBA expression, or None to leave it alone."""
        bits = getattr(expr, "bits", None)
        if not bits:
            return None

        leaves: dict[str, Expression] = {}
        try:
            nodes = self._collect(expr, leaves, 0)
        except _Unsupported:
            return None
        if not leaves or len(leaves) > self._max_vars or nodes > MAX_NODES:
            return None
        # A tangle worth rewriting has more operators than the template that would replace it.
        if nodes < 5:
            return None
        if any(getattr(leaf, "bits", None) != bits for leaf in leaves.values()):
            # mixed widths change what the identities mean; leave them alone
            return None

        names = list(leaves)
        env = {name: claripy.BVS(f"mba_{i}", bits, explicit_name=True) for i, name in enumerate(names)}
        variables = [env[name] for name in names]
        try:
            target = self._to_claripy(expr, env, bits)
        except (_Unsupported, KeyError):
            return None

        self.candidates += 1
        # Re-translate the AIL with concrete leaves rather than substituting into the AST: it is
        # the same walk, and it cannot go subtly wrong the way a replacement map can.
        def evaluate_target(concrete):
            return self._to_claripy(expr, dict(zip(names, concrete)), bits)

        target_signature = self._signature(evaluate_target, variables, bits)
        if target_signature is None:
            return None

        for label, builder in self._templates(names):
            if self._signature(builder, variables, bits) != target_signature:
                continue
            candidate = builder(variables)
            if not self._equivalent(target, candidate):
                # signatures agreed but the expressions differ: exactly what the proof is for
                self.verified_away += 1
                continue
            rebuilt = self._to_ail(label, [leaves[n] for n in names], bits, expr)
            if rebuilt is not None:
                self.simplified += 1
                l.debug("MBA: %s => %s", expr, rebuilt)
                return rebuilt
        return None

    @staticmethod
    def _equivalent(a, b) -> bool:
        solver = claripy.Solver()
        solver.add(a != b)
        try:
            return not solver.satisfiable()
        except Exception:  # pylint:disable=broad-except
            return False

    def _to_ail(self, label: str, operands: list[Expression], bits: int, original: Expression):
        """Build the AIL form of a matched template."""
        if self._ail_manager is None:
            return None
        idx = self._ail_manager.next_atom
        tags = original.tags

        def binop(op, a, b):
            return BinaryOp(idx(), op, [a, b], False, bits=bits, **tags)

        def unop(op, a):
            return UnaryOp(idx(), op, a, **tags)

        x = operands[0]
        y = operands[1] if len(operands) > 1 else None
        z = operands[2] if len(operands) > 2 else None
        table = {
            "x": lambda: x,
            "~x": lambda: unop("BitwiseNeg", x),
            "-x": lambda: unop("Neg", x),
            "x + y": lambda: binop("Add", x, y),
            "x - y": lambda: binop("Sub", x, y),
            "y - x": lambda: binop("Sub", y, x),
            "x ^ y": lambda: binop("Xor", x, y),
            "x & y": lambda: binop("And", x, y),
            "x | y": lambda: binop("Or", x, y),
            "~(x ^ y)": lambda: unop("BitwiseNeg", binop("Xor", x, y)),
            "-(x + y)": lambda: unop("Neg", binop("Add", x, y)),
            "x + y + z": lambda: binop("Add", binop("Add", x, y), z),
            "x ^ y ^ z": lambda: binop("Xor", binop("Xor", x, y), z),
            "(x ^ y) + z": lambda: binop("Add", binop("Xor", x, y), z),
            "(x & y) | z": lambda: binop("Or", binop("And", x, y), z),
        }
        builder = table.get(label)
        return builder() if builder is not None else None

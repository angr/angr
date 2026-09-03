from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import claripy

from angr.ailment.statement import Assignment
from angr.ailment.expression import (
    BinaryOp,
    Extract,
    Insert,
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


#: Random probes added to a signature. The zero/all-ones points pin a linear MBA exactly, but say
#: nothing about non-linear behaviour; these make an accidental signature collision very unlikely.
_PROBE_VECTORS = 6
#: Largest synthesised expression, in cost units (see _cost_of). Beyond this, stop searching.
_MAX_SYNTH_SIZE = 9
#: What a boolean operator costs relative to an arithmetic one.
#:
#: Counting nodes is the wrong objective here. `(a ^ b) + c + 1` and `c - ~(a ^ b)` compute the
#: same thing and the second has fewer nodes, but it is the *more* obfuscated of the two -- it
#: trades an addition for a bitwise negation. The point of this pass is to remove mixed
#: boolean-arithmetic, so boolean operators are priced accordingly and a candidate is only
#: accepted when it is cheaper by this measure than what it replaces.
_BOOLEAN_COST = 3
#: Enumeration is exponential in the variable count; three keeps the pool small.
_MAX_SYNTH_VARS = 3


class LinearMBASolver:
    """
    Synthesise the simplest expression matching an MBA's behaviour.

    Matching against a list of known identities only finds the identities on the list, and an
    obfuscator generates its templates.  This searches instead: it enumerates expressions over the
    subtree's own leaves from smallest upwards, keeping one representative per distinct *signature*
    -- its values on the zero/all-ones assignments plus a few random probes -- so the pool stays
    small however many expressions of a given size exist.  The first candidate whose signature
    matches the target is the smallest expression that behaves like it.

    A signature match is evidence, not proof.  Nothing is returned without the solver confirming
    equivalence over all inputs.
    """

    def __init__(self, ail_manager: Manager | None = None, max_size: int = _MAX_SYNTH_SIZE):
        self._ail_manager = ail_manager
        self._max_size = max_size
        self.attempted = 0
        self.synthesized = 0
        self.proof_rejected = 0
        self._helper = MBATemplateSimplifier(ail_manager=ail_manager)

    @staticmethod
    def _cost_of(expr, depth: int = 0) -> int:
        """Price an expression, charging more for the boolean operators MBA hides behind."""
        if depth > 64:
            return 1 << 20
        if isinstance(expr, BinaryOp):
            own = _BOOLEAN_COST if expr.op in _BOOLEAN_BINOPS else 1
            return own + sum(LinearMBASolver._cost_of(o, depth + 1) for o in expr.operands)
        if isinstance(expr, UnaryOp):
            own = _BOOLEAN_COST if expr.op in _BOOLEAN_UNOPS else 1
            return own + LinearMBASolver._cost_of(expr.operand, depth + 1)
        return 1

    @staticmethod
    def _probe_points(n: int, bits: int) -> list[list[int]]:
        mask = (1 << bits) - 1
        points = []
        for pattern in range(1 << n):
            points.append([mask if (pattern >> i) & 1 else 0 for i in range(n)])
        # deterministic pseudo-random probes: no seeding, and the same every run
        state = 0x9E3779B97F4A7C15
        for _ in range(_PROBE_VECTORS):
            row = []
            for _ in range(n):
                state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
                row.append(state & mask)
            points.append(row)
        return points

    def _signature_of(self, evaluate, points) -> tuple[int, ...] | None:
        out = []
        for row in points:
            try:
                value = evaluate(row)
            except Exception:  # pylint:disable=broad-except
                return None
            out.append(value)
        return tuple(out)

    def synthesize(self, expr: Expression):
        """Return the smallest expression equivalent to ``expr``, or None."""
        if self._ail_manager is None:
            return None
        bits = getattr(expr, "bits", None)
        if not bits:
            return None

        leaves: dict[str, Expression] = {}
        try:
            nodes = self._helper._collect(expr, leaves, 0)  # pylint:disable=protected-access
        except _Unsupported:
            return None
        n = len(leaves)
        if not n or n > _MAX_SYNTH_VARS or nodes < 3 or nodes > MAX_NODES:
            return None
        # Only search for something strictly cheaper than what we already have; there is no point
        # spending the enumeration to arrive back where we started, or somewhere worse.
        budget = min(self._max_size, self._cost_of(expr) - 1)
        if budget < 1:
            return None
        if any(getattr(leaf, "bits", None) != bits for leaf in leaves.values()):
            return None

        names = list(leaves)
        points = self._probe_points(n, bits)
        mask = (1 << bits) - 1

        def evaluate_target(row):
            env = {name: claripy.BVV(row[i], bits) for i, name in enumerate(names)}
            value = self._helper._to_claripy(expr, env, bits)  # pylint:disable=protected-access
            if value.op != "BVV":
                raise _Unsupported
            return value.args[0]

        self.attempted += 1
        target = self._signature_of(evaluate_target, points)
        if target is None:
            return None

        found = self._search(names, leaves, points, bits, mask, target, budget)
        if found is None:
            return None
        if not self._proves_equivalent(expr, found, names, leaves, bits):
            self.proof_rejected += 1
            return None
        self.synthesized += 1
        return found

    def _search(self, names, leaves, points, bits, mask, target, budget):
        """Bottom-up enumeration, one representative per signature."""
        idx = self._ail_manager.next_atom

        def sig(values):
            return tuple(v & mask for v in values)

        # size 1: the leaves themselves, and the constants worth trying
        pool: dict[tuple[int, ...], tuple[int, object]] = {}
        for i, name in enumerate(names):
            pool.setdefault(sig([row[i] for row in points]), (1, leaves[name]))
        for value in (0, 1, 2):
            pool.setdefault(sig([value] * len(points)), (1, Const(idx(), value & mask, bits)))

        by_size: dict[int, list[tuple[tuple[int, ...], object]]] = {1: [(k, e) for k, (_, e) in pool.items()]}

        def record(signature, size, builder):
            if signature in pool:
                return
            pool[signature] = (size, builder)
            by_size.setdefault(size, []).append((signature, builder))
            if signature == target:
                raise _Found(builder)

        try:
            if sig(target) in pool:
                return pool[target][1]
            for size in range(2, budget + 1):
                # unary
                for prev_sig, prev in by_size.get(size - _BOOLEAN_COST, []):
                    record(sig([(~v) for v in prev_sig]), size, UnaryOp(idx(), "BitwiseNeg", prev))
                for prev_sig, prev in by_size.get(size - 1, []):
                    record(sig([(-v) for v in prev_sig]), size, UnaryOp(idx(), "Neg", prev))
                # binary: split the budget between the two sides
                for op, fn, own in (
                    ("Add", lambda a, b: a + b, 1),
                    ("Sub", lambda a, b: a - b, 1),
                    ("And", lambda a, b: a & b, _BOOLEAN_COST),
                    ("Or", lambda a, b: a | b, _BOOLEAN_COST),
                    ("Xor", lambda a, b: a ^ b, _BOOLEAN_COST),
                ):
                    for left_size in range(1, size - own):
                        right_size = size - own - left_size
                        for ls, le in by_size.get(left_size, []):
                            for rs, re in by_size.get(right_size, []):
                                record(
                                    sig([fn(a, b) for a, b in zip(ls, rs)]),
                                    size,
                                    BinaryOp(idx(), op, [le, re], False, bits=bits),
                                )
        except _Found as hit:
            return hit.expression
        return None

    def _proves_equivalent(self, original, candidate, names, leaves, bits) -> bool:
        env = {name: claripy.BVS(f"mba_{i}", bits, explicit_name=True) for i, name in enumerate(names)}
        try:
            a = self._helper._to_claripy(original, env, bits)  # pylint:disable=protected-access
            b = self._helper._to_claripy(candidate, env, bits)  # pylint:disable=protected-access
        except (_Unsupported, KeyError):
            return False
        solver = claripy.Solver()
        solver.add(a != b)
        try:
            return not solver.satisfiable()
        except Exception:  # pylint:disable=broad-except
            return False


class _Found(Exception):
    def __init__(self, expression):
        super().__init__()
        self.expression = expression


#: Largest input space to enumerate exhaustively. Two bytes, or one 16-bit value.
MAX_INPUT_SPACE = 1 << 16
#: Points sampled when the input space is too large to enumerate. The result is then
#: evidence, not proof, and has to be checked another way before it is acted on.
SAMPLE_POINTS = 512

#: Give up on a value depending on more inputs than this.
MAX_COMPOSED_INPUTS = 2


_RUNAWAY = frozenset({"<runaway>"})


class ComposedMBASimplifier:
    """
    Simplify an MBA-obfuscated value by composing its definitions, then characterising it.

    Simplifying one expression at a time cannot work against this obfuscation. The VM spreads a
    computation over a chain of statements, each doing a little 8-bit arithmetic on one byte lane
    of a wider register, and every individual expression is irredundant -- it really does compute
    what it says. The redundancy only appears once the chain is composed: on cnicdriver a value
    reached through 338,000 nodes turns out to depend on two inputs.

    Composing the *expression* is hopeless for the same reason -- it is those 338,000 nodes. So
    this composes the *behaviour* instead: it walks the definition chain to find the true inputs,
    then evaluates the chain concretely, memoised, once per point of the input space.

    That the inputs are narrow is what makes this exact rather than approximate. A value depending
    on one byte is settled by 256 evaluations, and a candidate agreeing on all of them is not
    merely likely equivalent, it *is* equivalent -- the enumeration is the proof, and a stronger
    one than a solver query over an expression this size could deliver.
    """

    def __init__(self, ail_graph, ail_manager: Manager | None = None, max_inputs: int = MAX_COMPOSED_INPUTS):
        self._ail_manager = ail_manager
        self.max_inputs = max_inputs
        self._defs: dict[int, Expression] = {}
        for block in ail_graph:
            for stmt in block.statements or []:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    self._defs[stmt.dst.varid] = stmt.src
        self.characterized = 0
        self.simplified = 0
        # Definitions are shared, so the chain is a DAG: without memoising, walking it is
        # exponential in the sharing rather than linear in the nodes.
        self._input_memo: dict[int, frozenset[str] | None] = {}
        self._input_widths: dict[str, int] = {}

    #
    # composition
    #

    def _as_input(self, expr) -> tuple[str, int] | None:
        """
        Whether this is an atomic input, and how wide.

        A byte lane reaches a wide register through ``Extract(reg, 8bits@k)``, and it is that byte
        that the lane depends on -- not the whole register.  Taking the register as the input
        instead makes the space 2**64 and the value uncharacterisable, when the honest input space
        is 2**8.
        """
        if isinstance(expr, VirtualVariable):
            if expr.varid not in self._defs:
                return str(expr), expr.bits
            return None
        if isinstance(expr, Extract):
            base = expr.base
            if isinstance(base, VirtualVariable) and base.varid not in self._defs:
                return str(expr), expr.bits
            return None
        if self._children(expr) is None:
            return str(expr)[:64], getattr(expr, "bits", None) or 64
        return None

    def _inputs_of(self, expr, seen: frozenset[int], depth: int = 0) -> set[str] | None:
        """The leaves a value really depends on, following definitions. None if it runs away."""
        if depth > 400:
            return None
        if isinstance(expr, Const):
            return set()
        atomic = self._as_input(expr)
        if atomic is not None:
            self._input_widths[atomic[0]] = atomic[1]
            return {atomic[0]}
        if isinstance(expr, VirtualVariable):
            if expr.varid in self._defs and expr.varid not in seen:
                cached = self._input_memo.get(expr.varid)
                if cached is not None:
                    return set(cached) if cached is not _RUNAWAY else None
                got = self._inputs_of(self._defs[expr.varid], seen | {expr.varid}, depth + 1)
                self._input_memo[expr.varid] = _RUNAWAY if got is None else frozenset(got)
                return got
            return {str(expr)}
        children = self._children(expr)
        if children is None:
            return {str(expr)[:64]}  # opaque: a load, a call, a phi
        out: set[str] = set()
        for child in children:
            got = self._inputs_of(child, seen, depth + 1)
            if got is None:
                return None
            out |= got
            if len(out) > self.max_inputs:
                return None
        return out

    @staticmethod
    def _children(expr):
        if isinstance(expr, BinaryOp):
            return list(expr.operands)
        if isinstance(expr, (UnaryOp, Convert)):
            return [expr.operand]
        if isinstance(expr, Extract):
            return [expr.base]
        if isinstance(expr, Insert):
            return [expr.base, expr.value]
        return None

    def evaluate(self, expr, assignment: dict[str, int], cache: dict, depth: int = 0) -> int:
        """Value of ``expr`` under a concrete assignment of the true inputs."""
        if depth > 400:
            raise _Unsupported
        bits = getattr(expr, "bits", None) or 64
        mask = (1 << bits) - 1

        if isinstance(expr, Const):
            return expr.value & mask
        atomic = self._as_input(expr)
        if atomic is not None:
            if atomic[0] not in assignment:
                raise _Unsupported
            return assignment[atomic[0]] & mask
        if isinstance(expr, VirtualVariable):
            key = str(expr)
            if expr.varid in self._defs:
                hit = cache.get(expr.varid)
                if hit is None:
                    hit = self.evaluate(self._defs[expr.varid], assignment, cache, depth + 1)
                    cache[expr.varid] = hit
                return hit & mask
            if key not in assignment:
                raise _Unsupported
            return assignment[key] & mask
        if isinstance(expr, BinaryOp):
            a = self.evaluate(expr.operands[0], assignment, cache, depth + 1)
            b = self.evaluate(expr.operands[1], assignment, cache, depth + 1)
            op = expr.op
            if op == "Add":
                return (a + b) & mask
            if op == "Sub":
                return (a - b) & mask
            if op == "Mul":
                return (a * b) & mask
            if op == "And":
                return a & b & mask
            if op == "Or":
                return (a | b) & mask
            if op == "Xor":
                return (a ^ b) & mask
            if op == "Shl":
                return (a << (b & 0xFF)) & mask
            if op == "Shr":
                return (a >> (b & 0xFF)) & mask
            raise _Unsupported
        if isinstance(expr, UnaryOp):
            inner = self.evaluate(expr.operand, assignment, cache, depth + 1)
            if expr.op in _BOOLEAN_UNOPS:
                return (~inner) & mask
            if expr.op in _ARITH_UNOPS:
                return (-inner) & mask
            raise _Unsupported
        if isinstance(expr, Convert):
            inner = self.evaluate(expr.operand, assignment, cache, depth + 1)
            return inner & mask
        if isinstance(expr, Extract):
            base = self.evaluate(expr.base, assignment, cache, depth + 1)
            shift = self._byte_offset(expr) * 8
            return (base >> shift) & mask
        if isinstance(expr, Insert):
            base = self.evaluate(expr.base, assignment, cache, depth + 1)
            value = self.evaluate(expr.value, assignment, cache, depth + 1)
            width = getattr(expr.value, "bits", 8)
            shift = self._byte_offset(expr) * 8
            field = ((1 << width) - 1) << shift
            return ((base & ~field) | ((value << shift) & field)) & mask
        raise _Unsupported

    @staticmethod
    def _byte_offset(expr) -> int:
        offset = expr.offset
        if isinstance(offset, Const):
            return offset.value
        raise _Unsupported

    #
    # entry point
    #

    def characterize(self, expr) -> tuple[list[str], list[int], int] | None:
        """The value's true inputs and its complete table over them, or None."""
        bits = getattr(expr, "bits", None)
        if not bits:
            return None
        inputs = self._inputs_of(expr, frozenset())
        if not inputs or len(inputs) > self.max_inputs:
            return None

        names = sorted(inputs)
        widths = [self._input_widths.get(name) for name in names]
        if any(w is None for w in widths):
            return None
        space = 1
        for w in widths:
            space *= 1 << w
            if space > MAX_INPUT_SPACE:
                space = None
                break

        if space is not None:
            points = []
            for point in range(space):
                assignment, rest = {}, point
                for name, width in zip(names, widths):
                    assignment[name] = rest & ((1 << width) - 1)
                    rest >>= width
                points.append(assignment)
        else:
            # An input too wide to enumerate does not make the value uncharacterisable, only
            # unprovable by enumeration: sample it instead, and treat the result as evidence
            # rather than proof.
            points = []
            state = 0x9E3779B97F4A7C15
            for _ in range(SAMPLE_POINTS):
                assignment = {}
                for name, width in zip(names, widths):
                    state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
                    assignment[name] = state & ((1 << width) - 1)
                points.append(assignment)

        table = []
        for assignment in points:
            try:
                table.append(self.evaluate(expr, assignment, {}))
            except (_Unsupported, RecursionError):
                return None
        self.characterized += 1
        return names, table, space if space is not None else -len(points)

    @staticmethod
    def _width_of(name: str) -> int | None:
        """Bit width of an input, read off its printed form (``vvar_15180{s-16|1b}``)."""
        if "|" not in name or "b}" not in name:
            return None
        try:
            return int(name.split("|")[-1].split("b}")[0]) * 8
        except ValueError:
            return None

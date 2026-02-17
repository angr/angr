from __future__ import annotations

import logging
from collections.abc import Generator
from typing import cast, overload

import claripy
from claripy.annotation import RegionAnnotation, StridedIntervalAnnotation
from claripy.ast import BV, Base, Bool
from claripy.errors import BackendError, ClaripyOperationError

from angr.errors import AngrError

log = logging.getLogger(__name__)

commutative_operations = {
    "__and__",
    "__or__",
    "__xor__",
    "__add__",
    "__mul__",
    "And",
    "Or",
    "Xor",
}


class BalancerError(AngrError):
    """
    Base class for balancer errors.
    """


class BalancerUnsatError(BalancerError):
    """
    Exception raised when the balancer determines the constraints are unsatisfiable.
    """


class Balancer:
    """
    The Balancer is an equation redistributor. The idea is to take an AST and rebalance it to, for example, isolate
    unknown terms on one side of an inequality.
    """

    def __init__(self, c: Bool):
        self._truisms: list[Bool] = []
        self._ast_hash_map: dict[int, BV] = {}
        self._lower_bounds: dict[int, int] = {}
        self._upper_bounds: dict[int, int] = {}

        self.sat = True
        try:
            self._doit(c)
        except BalancerUnsatError:
            self.bounds = {}
            self.sat = False
        except BackendError:
            log.debug("Backend error in balancer.", exc_info=True)

    @property
    def compat_ret(self) -> tuple[bool, list[tuple[BV, BV]]]:
        return (self.sat, self.replacements)

    def _replacements_iter(self) -> Generator[tuple[BV, BV]]:
        all_keys = set(self._lower_bounds.keys()) | set(self._upper_bounds.keys())
        for k in all_keys:
            ast = self._ast_hash_map[k]
            max_int = (1 << len(ast)) - 1
            min_int = 0
            mn = self._lower_bounds.get(k, min_int)
            mx = self._upper_bounds.get(k, max_int)
            bound_si = claripy.BVS("bound", len(ast)).annotate(StridedIntervalAnnotation(1, mn, mx))
            log.debug("Yielding bound %s for %s.", bound_si, ast)
            if ast.op == "Reverse":
                yield (cast(BV, ast.args[0]), ast.intersection(bound_si).reversed)
            else:
                yield (ast, ast.intersection(bound_si))

    def _add_lower_bound(self, o: BV, b: int) -> None:
        if o.hash() in self._lower_bounds:
            old_b = self._lower_bounds[o.hash()]
            b = max(b, old_b)

        self._lower_bounds[o.hash()] = b
        self._ast_hash_map[o.hash()] = o

    def _add_upper_bound(self, o: BV, b: int) -> None:
        if o.hash() in self._upper_bounds:
            old_b = self._upper_bounds[o.hash()]
            b = min(b, old_b)

        self._upper_bounds[o.hash()] = b
        self._ast_hash_map[o.hash()] = o

    @property
    def replacements(self) -> list[tuple[BV, BV]]:
        return list(self._replacements_iter())

    #
    # AST helper functions
    #

    @staticmethod
    def _same_bound_bv(a: BV) -> BV:
        si = claripy.backends.vsa.simplify(a)
        mx = Balancer._max(a)
        mn = Balancer._min(a)
        si_anno = si.get_annotation(StridedIntervalAnnotation)
        stride = si_anno.stride if si_anno is not None else 0
        return claripy.BVS("bounds", len(a)).annotate(StridedIntervalAnnotation(stride, mn, mx))

    @staticmethod
    def _min(a: BV, signed=False) -> int:
        a = claripy.backends.vsa.simplify(a)
        if a.has_annotation_type(RegionAnnotation):
            region_annos = a.get_annotations_by_type(RegionAnnotation)
            if len(region_annos) == 1:
                a = next(iter(region_annos)).region_base_addr
            else:
                # unfortunately, this is a real abstract pointer
                # the minimum value will be 0 or MIN_INT
                if signed:
                    return -(1 << (len(a) - 1))
                return 0
        return claripy.backends.vsa.min(a, signed=signed)

    @staticmethod
    def _max(a: BV, signed=False) -> int:
        a = claripy.backends.vsa.simplify(a)
        if a.has_annotation_type(RegionAnnotation):
            region_annos = a.get_annotations_by_type(RegionAnnotation)
            if len(region_annos) == 1:
                a = next(iter(region_annos)).region_base_addr
            else:
                # unfortunately, this is a real abstract pointer
                # the minimum value will be 0 or MIN_INT
                if signed:
                    return (1 << (len(a) - 1)) - 1
                return (1 << len(a)) - 1
        return claripy.backends.vsa.max(a, signed=signed)

    @staticmethod
    def _range(a: BV, signed=False) -> tuple[int, int]:
        return (Balancer._min(a, signed=signed), Balancer._max(a, signed=signed))

    #
    # Truism alignment
    #

    @staticmethod
    def _align_truism(truism: Bool) -> Bool:
        outer_aligned = Balancer._align_ast(truism)
        inner_aligned = Bool(
            outer_aligned.op, (Balancer._align_ast(cast(BV, outer_aligned.args[0])), *outer_aligned.args[1:])
        )

        if not claripy.backends.vsa.identical(inner_aligned, truism):
            log.critical(
                "ERROR: the balancer is messing up an AST. This must be looked into. "
                "Please submit the binary and script to the angr project, if possible. "
                "Outer op is %s and inner op is %s.",
                truism.op,
                cast(BV, truism.args[0]).op,
            )
            return truism

        return cast(Bool, inner_aligned)

    @overload
    @staticmethod
    def _align_ast(a: Bool) -> Bool: ...

    @overload
    @staticmethod
    def _align_ast(a: BV) -> BV: ...

    @staticmethod
    def _align_ast(a: Bool | BV) -> Bool | BV:
        """
        Aligns the AST so that the argument with the highest cardinality is on the left.

        :return: a new AST.
        """

        try:
            if isinstance(a, BV):
                return Balancer._align_bv(a)
            if (
                isinstance(a, Bool)
                and len(a.args) == 2
                and cast(Bool, a.args[1]).cardinality > cast(Bool, a.args[0]).cardinality
            ):
                return Balancer._reverse_comparison(a)
            return a
        except BalancerError:
            return a

    @staticmethod
    def _reverse_comparison(a: Bool) -> Bool:
        lhs, rhs = cast(tuple[BV, BV], a.args)
        match a.op:
            case "__eq__":
                return rhs == lhs
            case "__ne__":
                return rhs != lhs
            case "ULT":
                return claripy.UGT(rhs, lhs)
            case "ULE":
                return claripy.UGE(rhs, lhs)
            case "UGT":
                return claripy.ULT(rhs, lhs)
            case "UGE":
                return claripy.ULE(rhs, lhs)
            case "SLT":
                return claripy.SGT(rhs, lhs)
            case "SLE":
                return claripy.SGE(rhs, lhs)
            case "SGT":
                return claripy.SLT(rhs, lhs)
            case "SGE":
                return claripy.SLE(rhs, lhs)
            case _:
                raise BalancerError(f"unable to reverse comparison {a.op}")

    @staticmethod
    def _align_bv(a: BV) -> BV:
        if a.op in commutative_operations:
            return BV(a.op, tuple(sorted(cast(tuple[BV, ...], a.args), key=lambda v: -v.cardinality)), length=a.length)

        match a.op:
            case "__sub__":
                return Balancer._align_sub(a)
            case _:
                return a

    @staticmethod
    def _align_sub(a: BV) -> BV:
        args = cast(tuple[BV, ...], a.args)

        cardinalities = [v.cardinality for v in args]
        if max(cardinalities) == cardinalities[0]:
            return a
        adjusted = tuple(-v for v in args[1:]) + args[:1]
        return BV("__add__", tuple(sorted(adjusted, key=lambda v: -v.cardinality)), length=a.length)

    #
    # Find bounds
    #

    def _doit(self, c: Bool) -> None:
        """
        This function processes the list of truisms and finds bounds for ASTs.
        """
        self._truisms.append(claripy.excavate_ite(c))

        processed_truisms = set()
        identified_assumptions = set()

        while len(self._truisms):
            truism = self._truisms.pop()

            if truism in processed_truisms:
                continue

            unpacked_truisms = Balancer._unpack_truisms(truism)
            if claripy.backends.vsa.is_false(truism):
                raise BalancerUnsatError

            processed_truisms.add(truism)
            if len(unpacked_truisms):
                self._truisms.extend(t for t in unpacked_truisms if not claripy.backends.vsa.is_true(t))
                continue

            if not Balancer._handleable_truism(truism):
                continue

            truism = Balancer._adjust_truism(truism)

            assumptions = Balancer._get_assumptions(truism)
            if truism not in identified_assumptions and len(assumptions):
                log.debug("Queued assumptions %s for truism %s.", assumptions, truism)
                self._truisms.extend(assumptions)
                identified_assumptions.update(assumptions)

            log.debug("Processing truism %s", truism)
            balanced_truism = self._balance(truism)
            log.debug("... handling")
            self._handle(balanced_truism)

    @staticmethod
    def _handleable_truism(t: Bool) -> bool:
        """
        Checks whether we can handle this truism. The truism should already be aligned.
        """
        if len(t.args) < 2:
            log.debug("can't do anything with an unop bool")
            return False
        lhs = cast(BV, t.args[0])
        rhs = cast(BV, t.args[1])
        if lhs.cardinality > 1 and rhs.cardinality > 1:
            log.debug("can't do anything because we have multiple multivalued guys")
            return False
        if t.op == "If":
            log.debug("can't handle If")
            return False
        return True

    @staticmethod
    def _adjust_truism(t: Bool) -> Bool:
        """
        Swap the operands of the truism if the unknown variable is on the right side and the concrete value is on the
        left side.
        """
        lhs, rhs = cast(tuple[BV, BV], t.args)
        if lhs.cardinality == 1 and rhs.cardinality > 1:
            return Balancer._reverse_comparison(t)
        return t

    #
    # Assumptions management
    #

    @staticmethod
    def _get_assumptions(t: Bool) -> list[Bool]:
        """
        Given a constraint, _get_assumptions() returns a set of constraints that are implicitly
        assumed to be true. For example, `x <= 10` would return `x >= 0`.
        """
        lhs = cast(BV, t.args[0])

        if t.op in ("ULE", "ULT"):
            return [lhs >= 0]
        if t.op in ("UGE", "UGT"):
            return [lhs <= 2 ** len(lhs) - 1]
        if t.op in ("SLE", "SLT"):
            return [claripy.SGE(lhs, -(1 << (len(lhs) - 1)))]
        if t.op in ("SGE", "SGT"):
            return [claripy.SLE(lhs, (1 << (len(lhs) - 1)) - 1)]
        return []

    #
    # Truism extractor
    #

    @staticmethod
    def _unpack_truisms(c: Bool) -> set[Bool]:
        """
        Given a constraint, _unpack_truisms() returns a set of constraints that must be True for
        this constraint to be True.
        """
        match c.op:
            case "And":
                return Balancer._unpack_truisms_and(c)
            case "Not":
                return Balancer._unpack_truisms_not(c)
            case "Or":
                return Balancer._unpack_truisms_or(c)
            case _:
                return set()

    @staticmethod
    def _unpack_truisms_and(c: Bool) -> set[Bool]:
        return set.union(*[Balancer._unpack_truisms(a) for a in cast(tuple[Bool, ...], c.args)])

    @staticmethod
    def _unpack_truisms_not(c: Bool) -> set[Bool]:
        arg = cast(Bool, c.args[0])
        if arg.op == "And":
            return Balancer._unpack_truisms(claripy.Or(*[claripy.Not(a) for a in arg.args]))
        if arg.op == "Or":
            return Balancer._unpack_truisms(claripy.And(*[claripy.Not(a) for a in arg.args]))
        return set()

    @staticmethod
    def _unpack_truisms_or(c: Bool) -> set[Bool]:
        args = cast(tuple[Bool, ...], c.args)
        vals = [claripy.backends.vsa.is_false(v) for v in args]
        if all(vals):
            raise BalancerUnsatError
        if vals.count(False) == 1:
            return Balancer._unpack_truisms(args[vals.index(False)])
        return set()

    #
    # Simplification routines
    #

    def _balance(self, truism: Bool) -> Bool:
        while True:
            log.debug("Balancing %s", truism)

            # can't balance single-arg bools (Not) for now
            if len(truism.args) == 1:
                return truism

            if not isinstance(truism.args[0], Base):
                return truism

            try:
                inner_aligned = Balancer._align_truism(truism)
                inner_lhs = cast(BV, inner_aligned.args[0])
                inner_rhs = cast(BV, inner_aligned.args[1])
                if inner_rhs.cardinality > 1:
                    log.debug("can't do anything because we have multiple multivalued guys")
                    return truism

                match inner_lhs.op:
                    case "Reverse":
                        balanced = Balancer._balance_reverse(inner_aligned)
                    case "__add__":
                        balanced = Balancer._balance_add(inner_aligned)
                    case "__sub__":
                        balanced = Balancer._balance_sub(inner_aligned)
                    case "ZeroExt":
                        balanced = Balancer._balance_zeroext(inner_aligned)
                    case "SignExt":
                        balanced = Balancer._balance_signext(inner_aligned)
                    case "Extract":
                        balanced = Balancer._balance_extract(inner_aligned)
                    case "__and__":
                        balanced = Balancer._balance_and(inner_aligned)
                    case "Concat":
                        balanced = Balancer._balance_concat(inner_aligned)
                    case "__lshift__":
                        balanced = Balancer._balance_lshift(inner_aligned)
                    case "If":
                        balanced = self._balance_if(inner_aligned)
                    case _:
                        log.debug("Balance handler %s not implemented.", truism.args[0].op)
                        return truism

                if balanced is inner_aligned:
                    return balanced
                truism = balanced
                continue
            except BalancerError:
                log.warning("Balance handler for operation %s raised exception.", truism.args[0].op)
                return truism

    @staticmethod
    def _balance_reverse(truism: Bool) -> Bool:
        if truism.op in ["__eq__", "__ne__"]:
            return BV(
                truism.op,
                (cast(BV, truism.args[0]).args[0], cast(BV, truism.args[1]).reversed),
                length=cast(BV, truism.args[1]).length,
            )
        return truism

    @staticmethod
    def _balance_add(truism: Bool) -> Bool:
        if len(truism.args) != 2:
            return truism
        lhs, old_rhs = cast(tuple[BV, BV], truism.args)
        lhs_args = cast(tuple[BV, ...], lhs.args)
        if all(a.concrete for a in lhs_args):
            # the old logic
            new_lhs = lhs_args[0]
            other_adds = lhs_args[1:]
        else:
            new_lhs = tuple(a for a in lhs_args if a.symbolic)
            if not new_lhs:
                return truism
            new_lhs = new_lhs[0] if len(new_lhs) == 1 else BV("__add__", new_lhs, length=lhs.length)
            other_adds = tuple(a for a in lhs_args if a.concrete)
            if not other_adds:
                return truism
        new_rhs = BV("__sub__", (old_rhs, *other_adds), length=lhs.length)
        return Bool(truism.op, (new_lhs, new_rhs))

    @staticmethod
    def _balance_sub(truism: Bool) -> Bool:
        if len(truism.args) != 2:
            return truism
        old_lhs = cast(BV, truism.args[0])
        new_lhs = cast(BV, old_lhs.args[0])
        old_rhs = cast(BV, truism.args[1])
        other_adds = old_lhs.args[1:]
        new_rhs = BV("__add__", (old_rhs, *other_adds), length=old_lhs.length)
        return Bool(truism.op, (new_lhs, new_rhs))

    @staticmethod
    def _balance_zeroext(truism: Bool) -> Bool:
        orig_lhs = cast(BV, truism.args[0])
        orig_rhs = cast(BV, truism.args[1])

        num_zeroes, inner = cast(tuple[int, BV], orig_lhs.args)
        other_side = orig_rhs[len(orig_rhs) - 1 : len(orig_rhs) - num_zeroes]

        if claripy.backends.vsa.is_true(other_side == 0):
            # We can safely eliminate this layer of ZeroExt
            new_args = (inner, orig_rhs[len(orig_rhs) - num_zeroes - 1 : 0])
            return Bool(truism.op, new_args)

        return truism

    @staticmethod
    def _balance_signext(truism: Bool) -> Bool:
        orig_lhs = cast(BV, truism.args[0])
        orig_rhs = cast(BV, truism.args[1])

        num_zeroes = cast(int, orig_lhs.args[0])
        left_side = orig_lhs[len(orig_rhs) - 1 : len(orig_rhs) - num_zeroes]
        other_side = orig_rhs[len(orig_rhs) - 1 : len(orig_rhs) - num_zeroes]

        # TODO: what if this is a set value, but *not* the same as other_side
        if claripy.backends.vsa.identical(left_side, other_side):
            # We can safely eliminate this layer of ZeroExt
            new_args = (orig_lhs.args[1], orig_rhs[len(orig_rhs) - num_zeroes - 1 : 0])
            return Bool(truism.op, new_args)

        return truism

    @staticmethod
    def _balance_extract(truism: Bool) -> Bool:
        lhs = cast(BV, truism.args[0])
        high, low, inner = cast(tuple[int, int, BV], lhs.args)
        inner_size = len(inner)
        rhs = cast(BV, truism.args[1])

        left_msb: BV | None
        left_msb_zero: bool | None

        if high < inner_size - 1:
            left_msb = inner[inner_size - 1 : high + 1]
            left_msb_zero = claripy.backends.vsa.is_true(left_msb == 0)
        else:
            left_msb = None
            left_msb_zero = None

        left_lsb: BV | None
        left_lsb_zero: bool | None

        if low > 0:
            left_lsb = inner[high - 1 : 0]
            left_lsb_zero = claripy.backends.vsa.is_true(left_lsb == 0)
        else:
            left_lsb = None
            left_lsb_zero = None

        if left_msb_zero and left_lsb_zero:
            new_left = inner
            new_right = claripy.Concat(
                claripy.BVV(0, len(cast(BV, left_msb))), rhs, claripy.BVV(0, len(cast(BV, left_lsb)))
            )
            return Bool(truism.op, (new_left, new_right))
        if left_msb_zero:
            new_left = inner
            new_right = claripy.Concat(claripy.BVV(0, len(cast(BV, left_msb))), rhs)
            return Bool(truism.op, (new_left, new_right))
        if left_lsb_zero:
            new_left = inner
            new_right = claripy.Concat(rhs, claripy.BVV(0, len(cast(BV, left_lsb))))
            return Bool(truism.op, (new_left, new_right))
        if low == 0 and rhs.op == "BVV" and truism.op not in {"SGE", "SLE", "SGT", "SLT"}:
            # single-valued rhs value with an unsigned operator
            # Eliminate Extract on lhs and zero-extend the value on rhs
            new_left = inner
            new_right = claripy.ZeroExt(inner.size() - rhs.size(), rhs)
            return Bool(truism.op, (new_left, new_right))

        return truism

    @staticmethod
    def _balance_and(truism: Bool) -> Bool:
        lhs = cast(BV, truism.args[0])
        if len(lhs.args) != 2:
            return truism
        op0, op1 = cast(tuple[BV, BV], lhs.args)

        if op1.op == "BVV":
            # if all low bits of right are 1 and all high bits of right are 0, then this is equivalent to Extract()
            v = cast(int, op1.args[0])
            low_ones = 0
            while v != 0:
                if v & 1 == 0:
                    # not all high bits are 0. abort
                    return truism
                low_ones += 1
                v >>= 1
            if low_ones == 0:
                # this should probably never happen
                new_left = BV("BVV", (0, op0.size()), length=op0.size())
                return Bool(truism.op, (new_left, truism.args[1]))

            if op0.op == "ZeroExt" and cast(int, op0.args[0]) + low_ones == op0.size():
                # ZeroExt(56, a) & 0xff == a  if a.size() == 8
                # we can safely remove __and__
                new_left = op0
                return Bool(truism.op, (new_left, truism.args[1]))

        return truism

    @staticmethod
    def _balance_concat(truism: Bool) -> Bool:
        lhs = cast(BV, truism.args[0])
        rhs = cast(BV, truism.args[1])
        size = len(lhs)
        left_msb = cast(BV, lhs.args[0])
        right_msb = rhs[size - 1 : size - len(left_msb)]

        if claripy.backends.vsa.is_true(left_msb == 0) and claripy.backends.vsa.is_true(right_msb == 0):
            # we can cut these guys off!
            lhs_args = cast(tuple[BV, ...], lhs.args)
            remaining_left = claripy.Concat(*lhs_args[1:])
            remaining_right = rhs[size - len(left_msb) - 1 : 0]
            return Bool(truism.op, (remaining_left, remaining_right))
        # TODO: handle non-zero single-valued cases
        return truism

    @staticmethod
    def _balance_lshift(truism: Bool) -> Bool:
        lhs = cast(BV, truism.args[0])
        rhs = cast(BV, truism.args[1])
        shift_amount_expr = cast(BV, lhs.args[1])
        expr = cast(BV, lhs.args[0])

        shift_amount_values = claripy.backends.vsa.eval(shift_amount_expr, 2)
        if len(shift_amount_values) != 1:
            return truism
        shift_amount = shift_amount_values[0]

        rhs_lower = claripy.Extract(shift_amount - 1, 0, rhs)
        rhs_lower_values = claripy.backends.vsa.eval(rhs_lower, 2)
        if len(rhs_lower_values) == 1 and rhs_lower_values[0] == 0:
            # we can remove the __lshift__

            return Bool(truism.op, (expr, rhs >> shift_amount))

        return truism

    def _balance_if(self, truism: Bool) -> Bool:
        lhs = cast(BV, truism.args[0])
        condition, true_expr, false_expr = cast(tuple[Bool, BV, BV], lhs.args)

        try:
            true_condition = getattr(true_expr, truism.op)(truism.args[1])
            false_condition = getattr(false_expr, truism.op)(truism.args[1])
        except ClaripyOperationError:
            # the condition was probably a Not (TODO)
            return truism

        can_true = claripy.backends.vsa.has_true(true_condition)
        can_false = claripy.backends.vsa.has_true(false_condition)
        must_true = claripy.backends.vsa.is_true(true_condition)
        must_false = claripy.backends.vsa.is_true(false_condition)

        if can_true and can_false:
            # always satisfiable
            return truism
        if not (can_true or can_false):
            # neither are satisfiable. This truism is fucked
            raise BalancerUnsatError
        if must_true or (can_true and not can_false):
            # it will always be true
            self._truisms.append(condition)
            return Bool(truism.op, (true_expr, truism.args[1]))
        if must_false or (can_false and not can_true):
            # it will always be false
            self._truisms.append(~condition)
            return Bool(truism.op, (false_expr, truism.args[1]))
        raise BalancerError("unhandled If balancing case")

    #
    # Constraint handlers
    #

    def _handle(self, truism: Bool) -> None:
        log.debug("Handling %s", truism)

        if claripy.backends.vsa.is_false(truism):
            raise BalancerUnsatError
        if truism.op in {"BoolV", "BoolS"} or cast(Base, truism.args[0]).cardinality == 1:
            # we are down to single-cardinality arguments, so our work is not
            # necessary
            return

        match truism.op:
            case "__eq__":
                self._handle_eq(truism)
            case "__ne__":
                self._handle_ne(truism)
            case "If":
                self._handle_if(truism)
            case "ULT" | "ULE" | "UGT" | "UGE" | "SLT" | "SLE" | "SGT" | "SGE":
                self._handle_comparison(truism)
            case _:
                log.debug("No handler for operation %s", truism.op)

    comparison_info = {
        "ULT": (True, False, True),
        "ULE": (True, True, True),
        "UGT": (False, False, True),
        "UGE": (False, True, True),
        "SLT": (True, False, False),
        "SLE": (True, True, False),
        "SGT": (False, False, False),
        "SGE": (False, True, False),
    }

    def _handle_comparison(self, truism: Bool) -> None:
        """
        Handles all comparisons.
        """

        is_lt, is_equal, is_unsigned = self.comparison_info[truism.op]
        lhs, rhs = cast(tuple[BV, BV], truism.args)

        size = len(lhs)
        int_max = 2**size - 1 if is_unsigned else 2 ** (size - 1) - 1
        int_min = -(2 ** (size - 1))

        left_min = Balancer._min(lhs, signed=not is_unsigned)
        left_max = Balancer._max(lhs, signed=not is_unsigned)
        right_min = Balancer._min(rhs, signed=not is_unsigned)
        right_max = Balancer._max(rhs, signed=not is_unsigned)

        bound_max = right_max if is_equal else (right_max - 1 if is_lt else right_max + 1)
        bound_min = right_min if is_equal else (right_min - 1 if is_lt else right_min + 1)

        if is_lt and bound_max < int_min:
            # if the bound max is negative and we're unsigned less than, we're fucked
            raise BalancerUnsatError
        if not is_lt and bound_min > int_max:
            # if the bound min is too big, we're fucked
            raise BalancerUnsatError

        current_min = int_min
        current_max = int_max

        if is_lt:
            current_max = min(int_max, left_max, bound_max)
            self._add_upper_bound(lhs, current_max)
        else:
            current_min = max(int_min, left_min, bound_min)
            self._add_lower_bound(lhs, current_min)

    def _handle_eq(self, truism: Bool) -> None:
        lhs, rhs = cast(tuple[BV, BV], truism.args)
        if rhs.cardinality != 1:
            common = Balancer._same_bound_bv(lhs.intersection(rhs))
            mn, mx = Balancer._range(common)
            self._add_upper_bound(lhs, mx)
            self._add_upper_bound(rhs, mx)
            self._add_lower_bound(lhs, mn)
            self._add_lower_bound(rhs, mn)
        else:
            mn, mx = Balancer._range(rhs)
            self._add_upper_bound(lhs, mx)
            self._add_lower_bound(lhs, mn)

    def _handle_ne(self, truism: Bool) -> None:
        lhs, rhs = cast(tuple[BV, BV], truism.args)
        if rhs.cardinality == 1:
            val = claripy.backends.vsa.eval(rhs, 1)[0]
            max_int = claripy.BVV((1 << len(lhs)) - 1, len(lhs)).args[0]

            if val == 0:
                self._add_lower_bound(lhs, val + 1)
            elif val in (max_int, val - 1):
                self._add_upper_bound(lhs, max_int - 1)

    def _handle_if(self, truism: Bool) -> None:
        condition, true_expr, false_expr = cast(tuple[Bool, BV, BV], truism.args)
        if claripy.backends.vsa.is_false(false_expr):
            self._truisms.append(condition)
        elif claripy.backends.vsa.is_false(true_expr):
            self._truisms.append(claripy.Not(condition))


def constraint_to_si(expr: Bool) -> tuple[bool, list[tuple[BV, BV]]]:
    """
    Convert a constraint to SI if possible.

    :param expr:
    :return:
    """

    return Balancer(expr).compat_ret

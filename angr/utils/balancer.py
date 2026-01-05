from __future__ import annotations

import logging
import operator
from collections.abc import Generator

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
        self._lower_bounds: dict[BV, int] = {}
        self._upper_bounds: dict[BV, int] = {}

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

    def _replacements_iter(self) -> Generator[tuple[BV, BV], None, None]:
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
                yield (ast.args[0], ast.intersection(bound_si).reversed)
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
    def _cardinality(a: Base) -> int:
        return a.cardinality if isinstance(a, Base) else 0

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
        inner_aligned = Bool(outer_aligned.op, (Balancer._align_ast(outer_aligned.args[0]), *outer_aligned.args[1:]))

        if not claripy.backends.vsa.identical(inner_aligned, truism):
            log.critical(
                "ERROR: the balancer is messing up an AST. This must be looked into. "
                "Please submit the binary and script to the angr project, if possible. "
                "Outer op is %s and inner op is %s.",
                truism.op,
                truism.args[0].op,
            )
            return truism

        return inner_aligned

    @staticmethod
    def _align_ast(a: Base) -> Base:
        """
        Aligns the AST so that the argument with the highest cardinality is on the left.

        :return: a new AST.
        """

        try:
            if isinstance(a, BV):
                return Balancer._align_bv(a)
            if isinstance(a, Bool) and len(a.args) == 2 and a.args[1].cardinality > a.args[0].cardinality:
                return Balancer._reverse_comparison(a)
            return a
        except BalancerError:
            return a

    @staticmethod
    def _reverse_comparison(a: Bool) -> Bool:
        match a.op:
            case "ULT":
                return claripy.UGT(a.args[1], a.args[0])
            case "ULE":
                return claripy.UGE(a.args[1], a.args[0])
            case "UGT":
                return claripy.ULT(a.args[1], a.args[0])
            case "UGE":
                return claripy.ULE(a.args[1], a.args[0])
            case "SLT":
                return claripy.SGT(a.args[1], a.args[0])
            case "SLE":
                return claripy.SGE(a.args[1], a.args[0])
            case "SGT":
                return claripy.SLT(a.args[1], a.args[0])
            case "SGE":
                return claripy.SLE(a.args[1], a.args[0])
            case _:
                raise BalancerError(f"unable to reverse comparison {a.op}")

    @staticmethod
    def _align_bv(a: BV) -> BV:
        if a.op in commutative_operations:
            return BV(a.op, tuple(sorted(a.args, key=lambda v: -Balancer._cardinality(v))), length=a.length)

        match a.op:
            case "__sub__":
                return Balancer._align_sub(a)
            case _:
                return a

    @staticmethod
    def _align_sub(a: BV) -> BV:
        cardinalities = [Balancer._cardinality(v) for v in a.args]
        if max(cardinalities) == cardinalities[0]:
            return a

        adjusted = tuple(operator.__neg__(v) for v in a.args[1:]) + a.args[:1]
        return BV("__add__", tuple(sorted(adjusted, key=lambda v: -Balancer._cardinality(v))), length=a.length)

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
        if t.args[0].cardinality > 1 and t.args[1].cardinality > 1:
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
        if t.args[0].cardinality == 1 and t.args[1].cardinality > 1:
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

        if t.op in ("ULE", "ULT"):
            return [t.args[0] >= 0]
        if t.op in ("UGE", "UGT"):
            return [t.args[0] <= 2 ** len(t.args[0]) - 1]
        if t.op in ("SLE", "SLT"):
            return [claripy.SGE(t.args[0], -(1 << (len(t.args[0]) - 1)))]
        if t.op in ("SGE", "SGT"):
            return [claripy.SLE(t.args[0], (1 << (len(t.args[0]) - 1)) - 1)]
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
        return set.union(*[Balancer._unpack_truisms(a) for a in c.args])

    @staticmethod
    def _unpack_truisms_not(c: Bool) -> set[Bool]:
        if c.args[0].op == "And":
            return Balancer._unpack_truisms(claripy.Or(*[claripy.Not(a) for a in c.args[0].args]))
        if c.args[0].op == "Or":
            return Balancer._unpack_truisms(claripy.And(*[claripy.Not(a) for a in c.args[0].args]))
        return set()

    @staticmethod
    def _unpack_truisms_or(c: Bool) -> set[Bool]:
        vals = [claripy.backends.vsa.is_false(v) for v in c.args]
        if all(vals):
            raise BalancerUnsatError
        if vals.count(False) == 1:
            return Balancer._unpack_truisms(c.args[vals.index(False)])
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
                if inner_aligned.args[1].cardinality > 1:
                    log.debug("can't do anything because we have multiple multivalued guys")
                    return truism

                match inner_aligned.args[0].op:
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
            return BV(truism.op, (truism.args[0].args[0], truism.args[1].reversed), length=truism.args[1].length)
        return truism

    @staticmethod
    def _balance_add(truism: Bool) -> Bool:
        if len(truism.args) != 2:
            return truism
        old_rhs = truism.args[1]
        lhs = truism.args[0]
        if all(a.concrete for a in lhs.args):
            # the old logic
            new_lhs = lhs.args[0]
            other_adds = lhs.args[1:]
        else:
            new_lhs = tuple(a for a in lhs.args if a.symbolic)
            if not new_lhs:
                return truism
            new_lhs = new_lhs[0] if len(new_lhs) == 1 else BV("__add__", new_lhs, length=lhs.length)
            other_adds = tuple(a for a in lhs.args if a.concrete)
            if not other_adds:
                return truism
        new_rhs = BV("__sub__", (old_rhs, *other_adds), length=truism.args[0].length)
        return Bool(truism.op, (new_lhs, new_rhs))

    @staticmethod
    def _balance_sub(truism: Bool) -> Bool:
        if len(truism.args) != 2:
            return truism
        new_lhs = truism.args[0].args[0]
        old_rhs = truism.args[1]
        other_adds = truism.args[0].args[1:]
        new_rhs = BV("__add__", (old_rhs, *other_adds), length=truism.args[0].length)
        return Bool(truism.op, (new_lhs, new_rhs))

    @staticmethod
    def _balance_zeroext(truism: Bool) -> Bool:
        num_zeroes, inner = truism.args[0].args
        other_side = truism.args[1][len(truism.args[1]) - 1 : len(truism.args[1]) - num_zeroes]

        if claripy.backends.vsa.is_true(other_side == 0):
            # We can safely eliminate this layer of ZeroExt
            new_args = (inner, truism.args[1][len(truism.args[1]) - num_zeroes - 1 : 0])
            return Bool(truism.op, new_args)

        return truism

    @staticmethod
    def _balance_signext(truism: Bool) -> Bool:
        num_zeroes = truism.args[0].args[0]
        left_side = truism.args[0][len(truism.args[1]) - 1 : len(truism.args[1]) - num_zeroes]
        other_side = truism.args[1][len(truism.args[1]) - 1 : len(truism.args[1]) - num_zeroes]

        # TODO: what if this is a set value, but *not* the same as other_side
        if claripy.backends.vsa.identical(left_side, other_side):
            # We can safely eliminate this layer of ZeroExt
            new_args = (truism.args[0].args[1], truism.args[1][len(truism.args[1]) - num_zeroes - 1 : 0])
            return Bool(truism.op, new_args)

        return truism

    @staticmethod
    def _balance_extract(truism: Bool) -> Bool:
        high, low, inner = truism.args[0].args
        inner_size = len(inner)

        if high < inner_size - 1:
            left_msb = inner[inner_size - 1 : high + 1]
            left_msb_zero = claripy.backends.vsa.is_true(left_msb == 0)
        else:
            left_msb = None
            left_msb_zero = None

        if low > 0:
            left_lsb = inner[high - 1 : 0]
            left_lsb_zero = claripy.backends.vsa.is_true(left_lsb == 0)
        else:
            left_lsb = None
            left_lsb_zero = None

        if left_msb_zero and left_lsb_zero:
            new_left = inner
            new_right = claripy.Concat(claripy.BVV(0, len(left_msb)), truism.args[1], claripy.BVV(0, len(left_lsb)))
            return Bool(truism.op, (new_left, new_right))
        if left_msb_zero:
            new_left = inner
            new_right = claripy.Concat(claripy.BVV(0, len(left_msb)), truism.args[1])
            return Bool(truism.op, (new_left, new_right))
        if left_lsb_zero:
            new_left = inner
            new_right = claripy.Concat(truism.args[1], claripy.BVV(0, len(left_lsb)))
            return Bool(truism.op, (new_left, new_right))
        if low == 0 and truism.args[1].op == "BVV" and truism.op not in {"SGE", "SLE", "SGT", "SLT"}:
            # single-valued rhs value with an unsigned operator
            # Eliminate Extract on lhs and zero-extend the value on rhs
            new_left = inner
            new_right = claripy.ZeroExt(inner.size() - truism.args[1].size(), truism.args[1])
            return Bool(truism.op, (new_left, new_right))

        return truism

    @staticmethod
    def _balance_and(truism: Bool) -> Bool:
        if len(truism.args[0].args) != 2:
            return truism
        op0, op1 = truism.args[0].args

        if op1.op == "BVV":
            # if all low bits of right are 1 and all high bits of right are 0, then this is equivalent to Extract()
            v = op1.args[0]
            low_ones = 0
            while v != 0:
                if v & 1 == 0:
                    # not all high bits are 0. abort
                    return truism
                low_ones += 1
                v >>= 1
            if low_ones == 0:
                # this should probably never happen
                new_left = BV("BVV", (0, truism.args[0].size()), length=truism.args[0].size())
                return Bool(truism.op, (new_left, truism.args[1]))

            if op0.op == "ZeroExt" and op0.args[0] + low_ones == op0.size():
                # ZeroExt(56, a) & 0xff == a  if a.size() == 8
                # we can safely remove __and__
                new_left = op0
                return Bool(truism.op, (new_left, truism.args[1]))

        return truism

    @staticmethod
    def _balance_concat(truism: Bool) -> Bool:
        size = len(truism.args[0])
        left_msb = truism.args[0].args[0]
        right_msb = truism.args[1][size - 1 : size - len(left_msb)]

        if claripy.backends.vsa.is_true(left_msb == 0) and claripy.backends.vsa.is_true(right_msb == 0):
            # we can cut these guys off!
            remaining_left = claripy.Concat(*truism.args[0].args[1:])
            remaining_right = truism.args[1][size - len(left_msb) - 1 : 0]
            return Bool(truism.op, (remaining_left, remaining_right))
        # TODO: handle non-zero single-valued cases
        return truism

    @staticmethod
    def _balance_lshift(truism: Bool) -> Bool:
        lhs = truism.args[0]
        rhs = truism.args[1]
        shift_amount_expr = lhs.args[1]
        expr = lhs.args[0]

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
        condition, true_expr, false_expr = truism.args[0].args

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
        if Balancer._cardinality(truism.args[0]) == 1:
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

        size = len(truism.args[0])
        int_max = 2**size - 1 if is_unsigned else 2 ** (size - 1) - 1
        int_min = -(2 ** (size - 1))

        left_min = Balancer._min(truism.args[0], signed=not is_unsigned)
        left_max = Balancer._max(truism.args[0], signed=not is_unsigned)
        right_min = Balancer._min(truism.args[1], signed=not is_unsigned)
        right_max = Balancer._max(truism.args[1], signed=not is_unsigned)

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
            self._add_upper_bound(truism.args[0], current_max)
        else:
            current_min = max(int_min, left_min, bound_min)
            self._add_lower_bound(truism.args[0], current_min)

    def _handle_eq(self, truism: Bool) -> None:
        lhs, rhs = truism.args
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
        lhs, rhs = truism.args
        if rhs.cardinality == 1:
            val = claripy.backends.vsa.eval(rhs, 1)[0]
            max_int = claripy.BVV((1 << len(lhs)) - 1, len(lhs)).args[0]

            if val == 0:
                self._add_lower_bound(lhs, val + 1)
            elif val in (max_int, val - 1):
                self._add_upper_bound(lhs, max_int - 1)

    def _handle_if(self, truism: Bool) -> None:
        if claripy.backends.vsa.is_false(truism.args[2]):
            self._truisms.append(truism.args[0])
        elif claripy.backends.vsa.is_false(truism.args[1]):
            self._truisms.append(~truism.args[0])


def constraint_to_si(expr: Bool) -> tuple[bool, list[tuple[BV, BV]]]:
    """
    Convert a constraint to SI if possible.

    :param expr:
    :return:
    """

    return Balancer(expr).compat_ret

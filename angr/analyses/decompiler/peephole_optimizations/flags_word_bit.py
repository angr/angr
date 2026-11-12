from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.expression import ITE, BinaryOp, Const, Convert, Expression, UnaryOp, VirtualVariable

from .base import PeepholeOptimizationExprBase
from .bool_scaled_mask import _int_const, _log2
from .known_bits import block_defs_resolver, known_bits


class _FlagConsumerFinder(AILBlockViewer):
    """Does an expression use a boolean as an integer (a carry-in: ``zext(b)``, ``w & 1``)?"""

    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_Convert(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.from_bits == 1 and expr.to_bits > 1:
            self.found = True
        return super()._handle_Convert(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op == "And" and expr.bits > 1 and any(_int_const(o) == 1 for o in expr.operands):
            self.found = True
        return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)


class _BitReader:
    """
    Bit ``k`` of an expression as a 1-bit expression, by exact bit algebra: through masks, merges (``|``, ``^``, ``+``
    of disjoint words), complements, constant shifts, extensions and the location-independent definitions of virtual
    variables. Refuses (None) anything else.
    """

    __slots__ = ("defs", "frame_regs", "hops", "manager", "path", "resolver", "tags", "use")

    def __init__(self, manager, block_defs, tags, frame_regs, use):
        self.manager = manager
        self.defs = block_defs.all_defs
        # registers holding frame addresses; None: unknown, stack variables are not followed
        self.frame_regs = frame_regs
        # (block, statement index) the variable being followed is read at; None: unknown
        self.use = use
        self.resolver = block_defs_resolver(block_defs)
        self.tags = tags
        self.hops = 0
        self.path: set[int] = set()

    def _const(self, value: int) -> Const:
        return Const(self.manager.next_atom(), value & 1, 1, **self.tags)

    def _not(self, b: Expression) -> Expression:
        if isinstance(b, Const):
            return self._const(1 - b.value_int)
        if isinstance(b, UnaryOp) and b.op == "Not":
            return b.operand
        return UnaryOp(self.manager.next_atom(), "Not", b, bits=1, **self.tags)

    def _join(self, op: str, a: Expression, b: Expression) -> Expression:
        # op: LogicalAnd, LogicalOr or CmpNE (xor) of two 1-bit values
        for x, y in ((a, b), (b, a)):
            if isinstance(x, Const):
                one = x.value_int & 1
                if op == "LogicalAnd":
                    return y if one else x
                if op == "LogicalOr":
                    return x if one else y
                return self._not(y) if one else y
        if a.likes(b):
            return self._const(0) if op == "CmpNE" else a
        return BinaryOp(self.manager.next_atom(), op, [a, b], False, bits=1, **self.tags)

    def _known(self, expr: Expression, k: int) -> Expression | None:
        z, o = known_bits(expr, self.resolver)
        if (z >> k) & 1:
            return self._const(0)
        if (o >> k) & 1:
            return self._const(1)
        return None

    def _clobberable(self, vvar: VirtualVariable) -> bool:
        # the single SSA version of a stack slot does not see a call writing it through an escaped frame address
        if not vvar.was_stack:
            return False
        if self.frame_regs is None or self.use is None:
            return True
        return self.defs.stack_read_clobbered(vvar, self.use[0], self.use[1], self.frame_regs)

    def bit(self, expr: Expression, k: int) -> Expression | None:
        if not 0 <= k < expr.bits:
            return None
        if isinstance(expr, Const):
            v = _int_const(expr)
            return None if v is None else self._const(v >> k)
        if expr.bits == 1:
            return self._flag(expr)
        r = self._bit(expr, k)
        return r if r is not None else self._known(expr, k)

    def _flag(self, expr: Expression) -> Expression | None:
        # a boolean that is itself a bit of a word (a truncation, a one-bit zero test) is read, never copied: the
        # copy would only move the bit read to another word
        if isinstance(expr, Convert):
            if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
                return None
            return self.bit(expr.operand, 0)
        if isinstance(expr, UnaryOp) and expr.op == "Not":
            r = self._flag(expr.operand)
            return None if r is None else self._not(r)
        if isinstance(expr, BinaryOp) and expr.op in {"CmpEQ", "CmpNE"}:
            op0, op1 = expr.operands
            if isinstance(op0, Const):
                op0, op1 = op1, op0
            if _int_const(op1) == 0 and op0.bits > 1:
                z, _ = known_bits(op0, self.resolver)
                maybe = ~z & ((1 << op0.bits) - 1)
                j = _log2(maybe)
                if j is not None:
                    r = self.bit(op0, j)
                    if r is None:
                        return None
                    return r if expr.op == "CmpNE" else self._not(r)
        return expr

    def _bit(self, expr: Expression, k: int) -> Expression | None:
        if isinstance(expr, VirtualVariable):
            if expr.varid in self.path or self._clobberable(expr):
                return None
            src = self.defs.get(expr.varid)
            if src is None or src.bits != expr.bits:
                return None
            self.path.add(expr.varid)
            self.hops += 1
            use, self.use = self.use, self.defs.def_location(expr.varid)
            r = self.bit(src, k)
            self.use = use
            self.path.discard(expr.varid)
            return r
        if isinstance(expr, UnaryOp):
            if expr.op != "BitwiseNeg" or expr.operand.bits != expr.bits:
                return None
            r = self.bit(expr.operand, k)
            return None if r is None else self._not(r)
        if isinstance(expr, Convert):
            if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
                return None
            if k < expr.from_bits:
                return self.bit(expr.operand, k)
            return self.bit(expr.operand, expr.from_bits - 1) if expr.is_signed else self._const(0)
        if isinstance(expr, ITE):
            if expr.cond.bits != 1:
                return None
            t, f = self.bit(expr.iftrue, k), self.bit(expr.iffalse, k)
            if not isinstance(t, Const) or not isinstance(f, Const):
                return None
            if t.value_int == f.value_int:
                return t
            c = self._flag(expr.cond)
            if c is None:
                return None
            return c if t.value_int else self._not(c)
        if not isinstance(expr, BinaryOp) or expr.floating_point or expr.vector_count:
            return None
        op0, op1 = expr.operands
        op = expr.op
        if op in {"Shl", "Shr", "Sar", "Mul"}:
            if op0.bits != expr.bits:
                return None
            if op == "Mul":
                j = _log2(_int_const(op1))
                if j is None:
                    op0, j = op1, _log2(_int_const(op0))
            else:
                j = _int_const(op1)
            if j is None or j < 0 or op0.bits != expr.bits:
                return None
            if op in {"Shl", "Mul"}:
                return self.bit(op0, k - j) if k >= j else self._const(0)
            if k + j < expr.bits:
                return self.bit(op0, k + j)
            return self.bit(op0, expr.bits - 1) if op == "Sar" else self._const(0)
        if op0.bits != expr.bits or op1.bits != expr.bits:
            return None
        if op == "Add":
            # a sum of words with no common possibly-set bit is their union
            z0, _ = known_bits(op0, self.resolver)
            z1, _ = known_bits(op1, self.resolver)
            if (z0 | z1) != (1 << expr.bits) - 1:
                return None
            op = "Or"
        join = {"And": "LogicalAnd", "Or": "LogicalOr", "Xor": "CmpNE"}.get(op)
        if join is None:
            return None
        a = self.bit(op0, k)
        if a is None:
            return None
        if isinstance(a, Const) and op != "Xor" and a.value_int == (op == "Or"):
            return a
        b = self.bit(op1, k)
        if b is None:
            return None
        return self._join(join, a, b)


class FlagsWordBitThroughVVar(PeepholeOptimizationExprBase):
    """
    ``v & (1 << k)`` ==> ``zext(b) << k`` when bit ``k`` of ``v`` is a boolean ``b`` that can be read out of the
    definitions of the variables in ``v``: flags words spelled out flag by flag, masked copies of them
    (``w & 0x8d5``), merges of two words (``w1 & M | w2 & ~M``) and complements. Only the boolean is copied to the
    test, so this works where inlining the whole (deep) word is refused, e.g. a devirtualized VM's loop condition
    ``(~flags & 1) != 0`` with ``flags = ~(cf | pf << 2 | ...)``. A test of several flags at once,
    ``(v & 0x41) == 0``, becomes the (negated) disjunction of the booleans.
    """

    __slots__ = ()

    NAME = "v & (1 << k) => the flag bit k of v's flags-word definition"
    expr_classes = (BinaryOp,)

    def _frame_regs(self) -> tuple[int, ...] | None:
        if self.project is None:
            return None
        arch = self.project.arch
        bp_as_gpr = False
        if self.kb is not None and self.func_addr is not None and self.kb.functions.contains_addr(self.func_addr):
            bp_as_gpr = self.kb.functions.get_by_addr(self.func_addr).info.get("bp_as_gpr", False)
        return tuple(off for off in (arch.sp_offset, None if bp_as_gpr else arch.bp_offset) if off is not None)

    def _mask_test(self, expr: BinaryOp, block_defs, use) -> Expression | None:
        # (v & M) ==/!= 0 with several bits in M: the disjunction of the flags, when every bit of M is one
        op0, op1 = expr.operands
        if isinstance(op0, Const):
            op0, op1 = op1, op0
        if _int_const(op1) != 0 or not isinstance(op0, BinaryOp) or op0.op != "And" or op0.floating_point:
            return None
        word, mask_expr = op0.operands
        if isinstance(word, Const):
            word, mask_expr = mask_expr, word
        mask = _int_const(mask_expr)
        if mask is None or word.bits != op0.bits:
            return None
        mask &= (1 << op0.bits) - 1
        if mask == 0 or _log2(mask) is not None:
            return None

        reader = _BitReader(self.manager, block_defs, expr.tags, self._frame_regs(), use)
        any_flag: Expression | None = None
        flags = 0
        for k in range(op0.bits):
            if not (mask >> k) & 1:
                continue
            b = reader.bit(word, k)
            if b is None:
                return None
            finder = _FlagConsumerFinder()
            finder.walk_expression(b)
            if finder.found:
                return None
            flags += not isinstance(b, Const)
            any_flag = b if any_flag is None else reader._join("LogicalOr", any_flag, b)
        if any_flag is None or reader.hops == 0 or flags < 2:
            # a single flag behind the mask is the single-bit case
            return None
        r = any_flag if expr.op == "CmpNE" else reader._not(any_flag)
        if expr.bits != 1:
            r = Convert(self.manager.next_atom(), 1, expr.bits, False, r, **expr.tags)
        return r

    def optimize(self, expr: BinaryOp, *, block_defs=None, block=None, stmt_idx=None, **kwargs):
        if expr.floating_point or block_defs is None or block_defs.all_defs is None:
            return None
        if expr.op in {"CmpEQ", "CmpNE"}:
            use = None if block is None or stmt_idx is None else (block, stmt_idx)
            return self._mask_test(expr, block_defs, use)
        if expr.op != "And":
            return None
        op0, op1 = expr.operands
        if isinstance(op0, Const):
            op0, op1 = op1, op0
        k = _log2(_int_const(op1))
        if k is None or op0.bits != expr.bits or k >= expr.bits:
            return None

        use = None if block is None or stmt_idx is None else (block, stmt_idx)
        reader = _BitReader(self.manager, block_defs, expr.tags, self._frame_regs(), use)
        b = reader.bit(op0, k)
        if b is None or reader.hops == 0:
            # an inline word is left to the other flag peepholes
            return None
        finder = _FlagConsumerFinder()
        finder.walk_expression(b)
        if finder.found:
            # a flag computed from another flag (adc/sbb chains) stays a variable; copying it nests without end
            return None

        conv = Convert(self.manager.next_atom(), 1, expr.bits, False, b, **expr.tags)
        if k == 0:
            return conv
        return BinaryOp(
            expr.idx,
            "Mul",
            [conv, Const(self.manager.next_atom(), 1 << k, expr.bits)],
            False,
            bits=expr.bits,
            **expr.tags,
        )

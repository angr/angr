"""
A fast, AIL-pattern-matching jump table resolver.

Most compiler-generated jump tables have a fixed, easily recognizable shape once the
containing block is lifted to AIL and simplified: the jump target is literally a load
from ``table + index * stride`` (x86 absolute tables), a PIC offset table
(``base + sign_extend(load(table + index * stride))``), or an ARM ``ldr pc``/Thumb
``tbb``/``tbh`` construct. These do not require symbolic execution to resolve.

``FastJumpTableResolver`` lifts the block to AIL, simplifies it, pattern-matches these
shapes, reads the table directly, and derives the entry count from a compare in the
predecessor. Anything it cannot confidently recognize resolves to ``(False, None)``, so
the slower, fully general :class:`JumpTableResolver` (registered immediately after it in
the default resolver list) handles everything the fast path skips. Correctness is never
traded for speed: on any ambiguity the fast path defers to the slow resolver.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, NamedTuple

from archinfo.arch_arm import is_arm_arch

from angr import ailment
from angr.ailment.expression import BinaryOp, Const, Convert, Load, Tmp
from angr.ailment.statement import Assignment, ConditionalJump, Jump
from angr.knowledge_plugins.cfg import IndirectJumpType

from .resolver import IndirectJumpResolver

try:
    from angr.engines import pcode
except ImportError:
    pcode = None

if TYPE_CHECKING:
    from angr.ailment.block import Block
    from angr.ailment.expression import Expression
    from angr.knowledge_plugins.functions import Function

l = logging.getLogger(name=__name__)


# Comparison operators whose operand order can be flipped so the constant sits on the
# right-hand side.
_FLIP_CMP = {"CmpLE": "CmpGE", "CmpLT": "CmpGT", "CmpGT": "CmpLT", "CmpGE": "CmpLE"}


class _TableMatch(NamedTuple):
    """The recovered shape of a jump table, as matched off a simplified AIL jump target."""

    kind: str  # "absolute" or "pic"
    table_addr: int
    entry_size: int
    offset_base: int | None  # for "pic": the base the loaded offset is added to
    signed: bool  # for "pic": whether the loaded offset is sign-extended


# Arches whose jump-table shapes this resolver understands. The "ALL" resolver list is
# applied to every architecture, so filter() must return False everywhere else.
SUPPORTED_ARCHES = frozenset({"X86", "AMD64", "ARMEL", "ARMHF", "ARMCortexM"})

# The restricted set of peephole optimizations needed to fold the tmp chain in a
# jump-table block down to a single Load-based Jump target. The full default set is
# unnecessary and slower.
_PEEPHOLE_OPT_NAMES = (
    "EagerEvaluation",
    "ShlToMul",
    "RewriteConvMul",
    "EvaluateConstConversions",
    "RemoveNoopConversions",
    "RemoveRedundantConversions",
    "RemoveCascadingConversions",
    "ConstantDereferences",
    "BasePointerOffsetAddN",
    "SimplifyPcRelativeLoads",
    "ConvShlShr",
)


def _load_peephole_opts():
    from angr.analyses.decompiler import peephole_optimizations as ppo

    return [getattr(ppo, name) for name in _PEEPHOLE_OPT_NAMES]


class FastJumpTableResolver(IndirectJumpResolver):
    """
    Resolve common compiler-generated jump tables by pattern-matching a simplified AIL
    block, avoiding the symbolic backward-slice machinery of :class:`JumpTableResolver`.
    """

    def __init__(self, project, resolve_calls: bool = True):
        super().__init__(project, timeless=False)
        self.resolve_calls = resolve_calls
        self._peephole_opts = None

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        if pcode is not None and isinstance(block.vex, pcode.lifter.IRSB):  # type: ignore
            # P-code IR is not supported.
            return False

        if self.project.arch.name not in SUPPORTED_ARCHES:
            return False

        if jumpkind == "Ijk_Boring":
            return True
        return bool(self.resolve_calls and jumpkind == "Ijk_Call")

    # helpers

    def _lift_and_simplify(self, addr: int, size: int | None, func_addr: int) -> Block | None:
        """
        Lift a single block to AIL and run the restricted block simplifier over it. The
        simplifier's propagator folds the tmp chain so the jump target carries the full
        table-address expression.

        :return: The simplified AIL block, or None if lifting/simplification failed.
        """
        if self._peephole_opts is None:
            self._peephole_opts = _load_peephole_opts()

        try:
            block = self.project.factory.block(addr, size=size)
            mgr = ailment.Manager(arch=self.project.arch)
            ail_block = ailment.IRSBConverter.convert(block.vex, mgr)
        except Exception:  # pylint:disable=broad-except
            l.debug("FastJumpTableResolver: failed to lift block %#x to AIL.", addr, exc_info=True)
            return None

        # Drop constant PC assignments (mirrors clinic._convert_all).
        ip_offset = self.project.arch.ip_offset
        ail_block.statements = [
            stmt
            for stmt in ail_block.statements
            if not (
                isinstance(stmt, ailment.Stmt.Assignment)
                and isinstance(stmt.dst, ailment.Expr.Register)
                and stmt.dst.reg_offset == ip_offset
                and isinstance(stmt.src, ailment.Expr.Const)
            )
        ]

        try:
            simp = self.project.analyses.AILBlockSimplifier(
                ail_block, mgr, func_addr, peephole_optimizations=self._peephole_opts
            )
        except Exception:  # pylint:disable=broad-except
            l.debug("FastJumpTableResolver: failed to simplify block %#x.", addr, exc_info=True)
            return None

        return simp.result_block

    def resolve(self, cfg, addr, func_addr, block, jumpkind, func_graph_complete: bool = True, **kwargs):
        if not cfg.kb.functions.contains_addr(func_addr):
            # the function must exist in the KB (angr issue #3768)
            return False, None

        func: Function = cfg.kb.functions[func_addr]

        jump_block = self._lift_and_simplify(addr, block.size, func_addr)
        if jump_block is None or not jump_block.statements:
            return False, None

        last = jump_block.statements[-1]
        if not isinstance(last, Jump):
            # ARM single-block tables end in a ConditionalJump; handled elsewhere.
            return False, None

        defs = self._defs_map(jump_block.statements)
        match = self._match_jump_target(last.target, defs)
        if match is None:
            return False, None

        num_entries = self._find_num_entries(cfg, func, addr, func_graph_complete)
        if num_entries is None:
            return False, None
        if num_entries < 2 or num_entries > max(cfg._indirect_jump_target_limit, 2):
            return False, None

        entries = self._read_entries(cfg, match, num_entries)
        if entries is None:
            return False, None

        # Alignment filter, mirroring the slow resolver.
        alignment = self.project.arch.instruction_alignment
        if alignment != 1:
            entries = [t for t in entries if t % alignment == 0]

        if len(entries) < 2:
            return False, None

        # Only accept when every entry is a valid target; on any doubt, defer to the
        # slow resolver rather than fabricate edges.
        if not all(self._is_target_valid(cfg, t) for t in entries):
            return False, None

        jumptable_size = len(entries) * match.entry_size
        ij = cfg.indirect_jumps.get(addr, None)
        if ij is not None:
            ij.jumptable = True
            ij.add_jumptable(match.table_addr, jumptable_size, match.entry_size, entries, is_primary=True)
            ij.resolved_targets = set(entries)
            ij.type = IndirectJumpType.Jumptable_AddressLoadedFromMemory

        l.debug(
            "FastJumpTableResolver resolved %#x: table %#x, %d entries.",
            addr,
            match.table_addr,
            len(entries),
        )
        return True, entries

    # matching helpers

    @staticmethod
    def _defs_map(statements) -> dict[int, Expression]:
        """Map a tmp index to the source expression of its (last) defining assignment."""
        defs: dict[int, Expression] = {}
        for stmt in statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, Tmp):
                defs[stmt.dst.tmp_idx] = stmt.src
        return defs

    @staticmethod
    def _deref(expr: Expression, defs: dict[int, Expression]) -> Expression:
        """Follow a chain of tmp definitions to the underlying expression."""
        seen: set[int] = set()
        while isinstance(expr, Tmp):
            if expr.tmp_idx in seen:
                break
            seen.add(expr.tmp_idx)
            nxt = defs.get(expr.tmp_idx)
            if nxt is None:
                break
            expr = nxt
        return expr

    def _split_const(self, expr: BinaryOp, defs: dict[int, Expression]) -> tuple[int, Expression] | None:
        """
        Given a binary op, return ``(const_value, other_operand)`` when exactly one
        operand dereferences to a constant.
        """
        a = self._deref(expr.operands[0], defs)
        b = self._deref(expr.operands[1], defs)
        if isinstance(a, Const) and not isinstance(b, Const):
            return a.value, b
        if isinstance(b, Const) and not isinstance(a, Const):
            return b.value, a
        return None

    def _parse_scaled_load_addr(self, addr_expr: Expression, defs: dict[int, Expression]) -> tuple[int, int] | None:
        """
        Match ``Add(base_const, Mul(index, stride_const))`` (in any operand order) and
        return ``(base_const, stride_const)``.
        """
        addr_expr = self._deref(addr_expr, defs)
        if not (isinstance(addr_expr, BinaryOp) and addr_expr.op == "Add"):
            return None
        split = self._split_const(addr_expr, defs)
        if split is None:
            return None
        base, other = split
        other = self._deref(other, defs)
        if not (isinstance(other, BinaryOp) and other.op == "Mul"):
            return None
        mul_split = self._split_const(other, defs)
        if mul_split is None:
            return None
        stride, _index = mul_split
        return base, stride

    def _strip_convert_to_load(self, expr: Expression, defs: dict[int, Expression]) -> tuple[bool, Load | None]:
        """Strip an optional Convert wrapper and return ``(signed, load_or_None)``."""
        signed = False
        expr = self._deref(expr, defs)
        if isinstance(expr, Convert):
            signed = expr.is_signed
            expr = self._deref(expr.operand, defs)
        if isinstance(expr, Load):
            return signed, expr
        return signed, None

    def _match_jump_target(self, target: Expression, defs: dict[int, Expression]) -> _TableMatch | None:
        """Recognize the supported jump-table shapes off a folded jump target expression."""
        e = self._deref(target, defs)

        # Absolute address table: Load(base + index * stride), stride == entry_size.
        if isinstance(e, Load):
            parsed = self._parse_scaled_load_addr(e.addr, defs)
            if parsed is not None:
                base, stride = parsed
                if stride == e.size:
                    return _TableMatch("absolute", base, e.size, None, False)
            return None

        # PIC offset table, form A: Add(base_const, Convert?(Load(table + index * es))).
        if isinstance(e, BinaryOp) and e.op == "Add":
            split = self._split_const(e, defs)
            if split is None:
                return None
            base_const, other = split
            signed, load = self._strip_convert_to_load(other, defs)
            if load is None:
                return None
            parsed = self._parse_scaled_load_addr(load.addr, defs)
            if parsed is None:
                return None
            tbl_base, stride = parsed
            if stride == load.size and tbl_base == base_const:
                return _TableMatch("pic", tbl_base, load.size, base_const, signed)
            return None

        # PIC offset table, form B: Convert(Add(Load(table + index * es), table_base)).
        if isinstance(e, Convert):
            signed = e.is_signed
            inner = self._deref(e.operand, defs)
            if isinstance(inner, BinaryOp) and inner.op == "Add":
                split = self._split_const(inner, defs)
                if split is None:
                    return None
                base_const, other = split
                other = self._deref(other, defs)
                if isinstance(other, Load):
                    parsed = self._parse_scaled_load_addr(other.addr, defs)
                    if parsed is not None:
                        tbl_base, stride = parsed
                        if stride == other.size and tbl_base == base_const:
                            return _TableMatch("pic", tbl_base, other.size, base_const, signed)
            return None

        return None

    # bound discovery

    def _find_num_entries(self, cfg, func: Function, block_addr: int, func_graph_complete: bool) -> int | None:
        """
        Recover the number of table entries from a bounds compare in the (single)
        predecessor of the jump block. Returns None when the shape is not a clean
        single-predecessor / two-successor jump table.
        """
        node = func.get_node(block_addr)
        if node is None or node not in func.transition_graph:
            return None
        preds = list(func.transition_graph.predecessors(node))
        if len(preds) != 1:
            return None
        pred = preds[0]
        succs = [s for s in func.transition_graph.successors(pred) if s.addr != pred.addr]
        if len(succs) != 2:
            return None

        pred_block = self._lift_and_simplify(pred.addr, pred.size, func.addr)
        if pred_block is None or not pred_block.statements:
            return None
        last = pred_block.statements[-1]
        if not isinstance(last, ConditionalJump):
            return None
        cond = last.condition
        if not (isinstance(cond, BinaryOp) and cond.op in _FLIP_CMP):
            return None

        # Normalize so the constant sits on the right-hand side: ``x OP n``.
        c0, c1 = cond.operands
        if isinstance(c1, Const) and not isinstance(c0, Const):
            n, op = c1.value, cond.op
        elif isinstance(c0, Const) and not isinstance(c1, Const):
            n, op = c0.value, _FLIP_CMP[cond.op]
        else:
            return None
        if n < 0:
            return None

        true_addr = self._const_value(last.true_target)
        false_addr = self._const_value(last.false_target)
        if true_addr == block_addr:
            positive = True
        elif false_addr == block_addr:
            positive = False
        else:
            return None

        # ``positive`` is whether ``x OP n`` must hold to reach the jump block. Only
        # upper-bounded tables (0 <= index <= K) are accepted.
        if positive:
            if op == "CmpLE":
                return n + 1
            if op == "CmpLT":
                return n
        else:
            if op == "CmpGT":  # not(x > n) => x <= n
                return n + 1
            if op == "CmpGE":  # not(x >= n) => x < n
                return n
        return None

    @staticmethod
    def _const_value(expr: Expression) -> int | None:
        return expr.value if isinstance(expr, Const) else None

    # entry extraction

    def _read_entries(self, cfg, match: _TableMatch, num_entries: int) -> list[int] | None:
        """Read ``num_entries`` targets from the table, applying the recovered transform."""
        arch_mask = (1 << self.project.arch.bits) - 1
        modulus = 1 << (match.entry_size * 8)
        sign_bit = 1 << (match.entry_size * 8 - 1)

        entries: list[int] = []
        for i in range(num_entries):
            raw = cfg._fast_memory_load_pointer(match.table_addr + i * match.entry_size, match.entry_size)
            if raw is None:
                return None
            if match.kind == "absolute":
                target = raw
            else:
                raw_s = raw - modulus if (match.signed and (raw & sign_bit)) else raw
                target = (match.offset_base + raw_s) & arch_mask
            entries.append(target)
        return entries

    # convenience for other checks

    @property
    def _is_arm(self) -> bool:
        return is_arm_arch(self.project.arch)

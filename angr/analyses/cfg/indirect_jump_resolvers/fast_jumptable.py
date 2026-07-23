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
from typing import TYPE_CHECKING

from archinfo.arch_arm import is_arm_arch

from angr import ailment

from .resolver import IndirectJumpResolver

try:
    from angr.engines import pcode
except ImportError:
    pcode = None

if TYPE_CHECKING:
    from angr.ailment.block import Block

l = logging.getLogger(name=__name__)


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
        # Implemented in a later step.
        return False, None

    # convenience for other checks

    @property
    def _is_arm(self) -> bool:
        return is_arm_arch(self.project.arch)

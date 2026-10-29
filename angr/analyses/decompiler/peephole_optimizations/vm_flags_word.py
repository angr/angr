from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, VirtualVariable
from angr.analyses.decompiler.ccall_rewriters.flags_word import FlagsWordBuilder, flag_bits, flags_word_ccall
from angr.utils.ail import BlockDefs

from .base import PeepholeOptimizationExprBase


class ExpandMaskedFlagsWord(PeepholeOptimizationExprBase):
    """
    ``eflags_all(op, d1, d2, nd) & F`` ==> ``word(op, d1, d2, nd) & F`` for a single flag F, where ``word`` is the flags
    word spelled out flag by flag, also when the ccall is the (location-independent) definition of a virtual
    variable. A whole flags word that a VM pushes stays a ccall; the flag tests on it reduce to the flags they read.
    """

    __slots__ = ()

    NAME = "Expand masked x86 flags words"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, block_defs: BlockDefs | None = None, **kwargs):
        if expr.op != "And" or expr.floating_point:
            return None
        op0, op1 = expr.operands
        if isinstance(op0, Const):
            op0, op1 = op1, op0
        if not (isinstance(op1, Const) and isinstance(op1.value, int)):
            return None
        word = op0
        if isinstance(word, VirtualVariable) and block_defs is not None and block_defs.all_defs is not None:
            # only the graph-wide definitions: they are valid wherever the vvar is read
            word = block_defs.all_defs.get(word.varid)
            if word is None:
                return None
        split = flags_word_ccall(word)
        if split is None or split[0] != "X86":
            return None
        mask = op1.value_int & 0xFFFFFFFF
        if mask & ~flag_bits("X86") or mask.bit_count() != 1:
            # a single flag test reduces to that flag; a multi-flag merge reads better as the ccall
            return None
        builder = FlagsWordBuilder(self.manager, "X86", word.tags)
        built = builder.build(split[1], *word.operands[1:], self.manager.next_atom())
        if built is None:
            return None
        return BinaryOp(expr.idx, "And", [built, op1], expr.signed, bits=expr.bits, **expr.tags)

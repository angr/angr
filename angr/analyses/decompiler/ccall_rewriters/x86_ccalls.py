from __future__ import annotations

from angr.ailment import Expr
from angr.ailment.expression import Call, Convert, VirtualVariable
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.analyses.decompiler.x87_fsw import evaluate_over_fsw, fsw_predicate
from angr.engines.vex.claripy.ccall import data
from angr.procedures.definitions import SIM_LIBRARIES

from .rewriter_base import CCallRewriterBase

X86_CondTypes = data["X86"]["CondTypes"]
X86_OpTypes = data["X86"]["OpTypes"]
X86_CondBitMasks = data["X86"]["CondBitMasks"]
X86_CondBitOffsets = data["X86"]["CondBitOffsets"]

# conditions on flags stored verbatim (G_CC_OP_COPY), e.g. a jcc in a later block than its ucomisd/comisd:
# the flag mask tested and whether the condition holds when a masked flag is set
_COPY_FLAG_TESTS = {
    X86_CondTypes["CondZ"]: ("G_CC_MASK_Z", True),
    X86_CondTypes["CondNZ"]: ("G_CC_MASK_Z", False),
    X86_CondTypes["CondP"]: ("G_CC_MASK_P", True),
    X86_CondTypes["CondNP"]: ("G_CC_MASK_P", False),
    X86_CondTypes["CondB"]: ("G_CC_MASK_C", True),
    X86_CondTypes["CondNB"]: ("G_CC_MASK_C", False),
    X86_CondTypes["CondBE"]: ("G_CC_MASK_C|G_CC_MASK_Z", True),
    X86_CondTypes["CondNBE"]: ("G_CC_MASK_C|G_CC_MASK_Z", False),
}


def _flag_mask(masks, names: str) -> int:
    mask = 0
    for name in names.split("|"):
        bit = masks[name]
        assert isinstance(bit, int)
        mask |= bit
    return mask


X86_Win32_TIB_Funcs = {
    0x18: "NtGetCurrentTeb",
    0x30: "NtGetCurrentPeb",
}


class X86CCallRewriter(CCallRewriterBase):
    """
    Implements VEX ccall rewriter for X86.

    From libVEX, a summary of the field usages is::

        Operation          DEP1               DEP2               NDEP
        -----------------------------------------------------------------
        add/sub/mul        first arg          second arg         unused
        adc/sbb            first arg          (second arg)
                                              XOR old_carry      old_carry
        and/or/xor         result             zero               unused
        inc/dec            result             zero               old_carry
        shl/shr/sar        result             subshifted-        unused
                                              result
        rol/ror            result             zero               old_flags
        copy               old_flags          zero               unused.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        callee = self._original_callee(ccall)
        if callee == "x86g_calculate_FXAM":
            return self._rewrite_fxam(ccall)
        if callee in {"x86g_create_mxcsr", "x86g_create_fpucw"}:
            return self._rewrite_control_word_read(ccall, callee[len("x86g_") :])
        r = self._rewrite_livein_flags(ccall, callee, "x86g_", "x86g_calculate_eflags_all", "x86g_calculate_eflags_c")
        if r is not None:
            return r
        if callee == "x86g_calculate_condition":
            cond = ccall.operands[0]
            op = ccall.operands[1]
            dep_1 = ccall.operands[2]
            dep_2 = ccall.operands[3]
            ndep = ccall.operands[4]
            if isinstance(cond, Expr.Const) and isinstance(op, Expr.Const):
                cond_v = cond.value
                op_v = op.value
                fp_cond = self._rewrite_fp_condition(ccall, cond_v, op_v, dep_1, dep_2, ndep)
                if fp_cond is not None:
                    return fp_cond
                if op_v == X86_OpTypes["G_CC_OP_COPY"] and cond_v in _COPY_FLAG_TESTS:
                    mask_names, flag_set = _COPY_FLAG_TESTS[cond_v]
                    return self._copied_flag_test(ccall, dep_1, _flag_mask(X86_CondBitMasks, mask_names), flag_set)
                if cond_v == X86_CondTypes["CondLE"]:
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 <=s dep_2
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            X86_OpTypes["G_CC_OP_SUBB"],
                            X86_OpTypes["G_CC_OP_SUBW"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            X86_OpTypes["G_CC_OP_SUBB"],
                            X86_OpTypes["G_CC_OP_SUBW"],
                            ccall.tags,
                        )

                        r = Expr.BinaryOp(ccall.idx, "CmpLE", (dep_1, dep_2), signed=True, bits=1, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == X86_CondTypes["CondO"]:
                    op_v = op.value
                    ret_cond = None
                    if op_v in {
                        X86_OpTypes["G_CC_OP_UMULB"],
                        X86_OpTypes["G_CC_OP_UMULW"],
                        X86_OpTypes["G_CC_OP_UMULL"],
                    }:
                        # dep_1 * dep_2 >= max_signed_byte/word/dword
                        ret = Expr.BinaryOp(
                            self.ail_manager.next_atom(),
                            "Mul",
                            (dep_1, dep_2),
                            bits=dep_1.bits * 2,
                            **ccall.tags,
                        )
                        max_signed = Expr.Const(
                            self.ail_manager.next_atom(),
                            (1 << (dep_1.bits - 1)),
                            bits=dep_1.bits * 2,
                            **ccall.tags,
                        )
                        ret_cond = Expr.BinaryOp(
                            self.ail_manager.next_atom(), "CmpGE", (ret, max_signed), signed=False, bits=1, **ccall.tags
                        )
                    elif op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # dep_1 + dep_2 >= max_signed_byte/word/dword
                        ret = Expr.BinaryOp(
                            self.ail_manager.next_atom(),
                            "Add",
                            (dep_1, dep_2),
                            bits=dep_1.bits,
                            **ccall.tags,
                        )
                        max_signed = Expr.Const(
                            self.ail_manager.next_atom(),
                            (1 << (dep_1.bits - 1)),
                            bits=dep_1.bits,
                            **ccall.tags,
                        )
                        ret_cond = Expr.BinaryOp(
                            self.ail_manager.next_atom(), "CmpGE", (ret, max_signed), signed=False, bits=1, **ccall.tags
                        )
                    elif op_v in {
                        X86_OpTypes["G_CC_OP_INCB"],
                        X86_OpTypes["G_CC_OP_INCW"],
                        X86_OpTypes["G_CC_OP_INCL"],
                    }:
                        # dep_1 is the result
                        overflowed = Expr.Const(
                            self.ail_manager.next_atom(),
                            1 << (dep_1.bits - 1),
                            dep_1.bits,
                            **ccall.tags,
                        )
                        ret_cond = Expr.BinaryOp(
                            self.ail_manager.next_atom(),
                            "CmpEQ",
                            (dep_1, overflowed),
                            signed=False,
                            bits=1,
                            **ccall.tags,
                        )

                    if ret_cond is not None:
                        return Expr.ITE(
                            ccall.idx,
                            ret_cond,
                            Expr.Const(self.ail_manager.next_atom(), 1, ccall.bits, **ccall.tags),
                            Expr.Const(self.ail_manager.next_atom(), 0, ccall.bits, **ccall.tags),
                            **ccall.tags,
                        )
                elif cond_v == X86_CondTypes["CondZ"]:
                    op_v = op.value
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # dep_1 + dep_2 == 0
                        ret = Expr.BinaryOp(
                            self.ail_manager.next_atom(),
                            "Add",
                            (dep_1, dep_2),
                            bits=dep_1.bits,
                            **ccall.tags,
                        )
                        zero = Expr.Const(
                            self.ail_manager.next_atom(),
                            0,
                            dep_1.bits,
                            **ccall.tags,
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpEQ",
                            (ret, zero),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(
                            self.ail_manager.next_atom(), cmp.bits, ccall.bits, False, cmp, **ccall.tags
                        )
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 - dep_2 == 0
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpEQ",
                            (dep_1, dep_2),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(
                            self.ail_manager.next_atom(), cmp.bits, ccall.bits, False, cmp, **ccall.tags
                        )
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                    }:
                        # dep_1 == 0
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpEQ",
                            (dep_1, Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits, **ccall.tags)),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(
                            self.ail_manager.next_atom(), cmp.bits, ccall.bits, False, cmp, **ccall.tags
                        )
                elif cond_v == X86_CondTypes["CondL"]:
                    op_v = op.value
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 - dep_2 < 0
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLT",
                            (dep_1, dep_2),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(
                            self.ail_manager.next_atom(), cmp.bits, ccall.bits, False, cmp, **ccall.tags
                        )
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                    }:
                        # dep_1 < 0
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLT",
                            (dep_1, Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits, **ccall.tags)),
                            True,
                            **ccall.tags,
                        )
                        return Expr.Convert(
                            self.ail_manager.next_atom(), cmp.bits, ccall.bits, False, cmp, **ccall.tags
                        )
                elif cond_v in {
                    X86_CondTypes["CondBE"],
                    X86_CondTypes["CondB"],
                }:
                    op_v = op.value
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # dep_1 + dep_2 <= 0  if CondBE
                        # dep_1 + dep_2 < 0   if CondB
                        ret = Expr.BinaryOp(
                            self.ail_manager.next_atom(),
                            "Add",
                            (dep_1, dep_2),
                            signed=False,
                            bits=dep_1.bits,
                            **ccall.tags,
                        )
                        zero = Expr.Const(
                            self.ail_manager.next_atom(),
                            0,
                            dep_1.bits,
                            **ccall.tags,
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (ret, zero),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(
                            self.ail_manager.next_atom(), cmp.bits, ccall.bits, False, cmp, **ccall.tags
                        )
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 <= dep_2  if CondBE
                        # dep_1 < dep_2   if CondB
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            X86_OpTypes["G_CC_OP_SUBB"],
                            X86_OpTypes["G_CC_OP_SUBW"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            X86_OpTypes["G_CC_OP_SUBB"],
                            X86_OpTypes["G_CC_OP_SUBW"],
                            ccall.tags,
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (dep_1, dep_2),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(
                            self.ail_manager.next_atom(), cmp.bits, ccall.bits, False, cmp, **ccall.tags
                        )
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                    }:
                        # dep_1 <= 0  if CondBE
                        # dep_1 < 0   if CondB
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (dep_1, Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits, **ccall.tags)),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(
                            self.ail_manager.next_atom(), cmp.bits, ccall.bits, False, cmp, **ccall.tags
                        )
        elif callee == "x86g_use_seg_selector":
            seg_selector = ccall.operands[2]
            virtual_addr = ccall.operands[3]
            while isinstance(seg_selector, Convert):
                seg_selector = seg_selector.operands[0]
            if (
                self.project.simos.name == "Win32"
                and isinstance(seg_selector, VirtualVariable)
                and seg_selector.was_reg
                and self.project.arch.register_names.get(seg_selector.reg_offset, "") == "fs"
                and isinstance(virtual_addr, Expr.Const)
                and virtual_addr.value_int in X86_Win32_TIB_Funcs
            ):
                accessor_name = X86_Win32_TIB_Funcs[virtual_addr.value_int]
                prototype = SIM_LIBRARIES["ntdll.dll"][0].get_prototype(accessor_name, deref=True)
                returnty_bits = ccall.bits
                if prototype is not None:
                    prototype = prototype.with_arch(self.project.arch)
                    if prototype.returnty and prototype.returnty.size:
                        returnty_bits = prototype.returnty.size
                call_expr = Call(
                    ccall.idx,
                    X86_Win32_TIB_Funcs[virtual_addr.value_int],
                    args=[],
                    bits=returnty_bits,
                    **ccall.tags,
                )
                variable_map_of(self.ail_manager).set_prototype(call_expr, prototype)
                call_expr.tags["is_prototype_guessed"] = False
                ref_expr = Expr.UnaryOp(self.ail_manager.next_atom(), "Reference", call_expr, **ccall.tags)
                if returnty_bits == ccall.bits:
                    return ref_expr
                return Expr.Convert(
                    self.ail_manager.next_atom(), returnty_bits, ccall.bits, False, ref_expr, **ccall.tags
                )
        return None

    def _rewrite_fp_condition(
        self,
        ccall: Expr.VEXCCallExpression,
        cond_v: int,
        op_v: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
        ndep: Expr.Expression,
    ) -> Expr.Expression | None:
        """
        Fold a condition over flags derived from an x87 status word (fcom or fxam; fnstsw ax; test ah, imm / sahf /
        cmp ah) into the IEEE comparison or classification test it implements.
        """
        if op_v == X86_OpTypes["G_CC_OP_COPY"]:
            # only the flag bits the condition reads must be known (sahf keeps the old OF)
            needed = _COND_FLAG_MASKS.get(cond_v & ~1)
            if needed is None:
                return None
            dep_1 = Expr.BinaryOp(None, "And", [dep_1, Expr.Const(None, needed, dep_1.bits)], False, bits=dep_1.bits)
        table = evaluate_over_fsw([dep_1, dep_2, ndep])
        if table is None:
            return None
        true_set = set()
        for outcome, values in table.values.items():
            flags = _x86_flags(op_v, *values)
            if flags is None:
                return None
            taken = _x86_condition(cond_v, flags)
            if taken is None:
                return None
            if taken:
                true_set.add(outcome)
        pred = fsw_predicate(table, frozenset(true_set), self.ail_manager.next_atom(), self.ail_manager, 1, ccall.tags)
        if pred is None:
            return None
        return Expr.Convert(ccall.idx, 1, ccall.bits, False, pred, **ccall.tags)

    def _fix_size(self, expr, op_v: int, type_8bit, type_16bit, tags):
        if op_v == type_8bit:
            bits = 8
        elif op_v == type_16bit:
            bits = 16
        else:
            bits = 32
        if bits < 32:
            if isinstance(expr, Expr.Const):
                return Expr.Const(expr.idx, expr.value & ((1 << bits) - 1), bits, **tags)
            return Expr.Convert(self.ail_manager.next_atom(), 32, bits, False, expr, **tags)
        return expr


_OP_NBITS = {
    "B": 8,
    "W": 16,
    "L": 32,
}
_OP_NAMES = {v: k for k, v in X86_OpTypes.items() if v is not None}
_COND_FLAG_MASKS = {
    X86_CondTypes["CondO"]: 0x800,
    X86_CondTypes["CondB"]: 0x1,
    X86_CondTypes["CondZ"]: 0x40,
    X86_CondTypes["CondBE"]: 0x41,
    X86_CondTypes["CondS"]: 0x80,
    X86_CondTypes["CondP"]: 0x4,
    X86_CondTypes["CondL"]: 0x880,
    X86_CondTypes["CondLE"]: 0x8C0,
}


def _parity(v: int) -> int:
    return 1 if (v & 0xFF).bit_count() % 2 == 0 else 0


def _x86_flags(op_v: int, dep_1: int, dep_2: int, ndep: int) -> tuple[int, int, int, int, int] | None:
    """
    Compute (cf, pf, zf, sf, of) for a constant cc_op with concrete dependencies. Only the ops that show up around
    x87 comparisons are supported.
    """
    if op_v == X86_OpTypes["G_CC_OP_COPY"]:
        return dep_1 & 1, (dep_1 >> 2) & 1, (dep_1 >> 6) & 1, (dep_1 >> 7) & 1, (dep_1 >> 11) & 1
    name = _OP_NAMES.get(op_v)
    if name is None:
        return None
    nbits = _OP_NBITS.get(name[-1])
    if nbits is None:
        return None
    mask = (1 << nbits) - 1
    top = 1 << (nbits - 1)
    kind = name[len("G_CC_OP_") : -1]
    d1, d2 = dep_1 & mask, dep_2 & mask
    if kind == "LOGIC":
        res = d1
        cf = of = 0
    elif kind == "SUB":
        res = (d1 - d2) & mask
        cf = 1 if d1 < d2 else 0
        of = 1 if ((d1 ^ d2) & (d1 ^ res)) & top else 0
    elif kind == "ADD":
        res = (d1 + d2) & mask
        cf = 1 if res < d1 else 0
        of = 1 if (~(d1 ^ d2) & (d1 ^ res)) & top else 0
    elif kind == "INC":
        res = d1
        cf = ndep & 1
        of = 1 if res == top else 0
    elif kind == "DEC":
        res = d1
        cf = ndep & 1
        of = 1 if res == top - 1 else 0
    else:
        return None
    return cf, _parity(res), 1 if res == 0 else 0, 1 if res & top else 0, of


def _x86_condition(cond_v: int, flags: tuple[int, int, int, int, int]) -> bool | None:
    cf, pf, zf, sf, of = flags
    base = cond_v & ~1
    if base == X86_CondTypes["CondO"]:
        r = of
    elif base == X86_CondTypes["CondB"]:
        r = cf
    elif base == X86_CondTypes["CondZ"]:
        r = zf
    elif base == X86_CondTypes["CondBE"]:
        r = cf | zf
    elif base == X86_CondTypes["CondS"]:
        r = sf
    elif base == X86_CondTypes["CondP"]:
        r = pf
    elif base == X86_CondTypes["CondL"]:
        r = sf ^ of
    elif base == X86_CondTypes["CondLE"]:
        r = (sf ^ of) | zf
    else:
        return None
    return bool(r ^ (cond_v & 1))

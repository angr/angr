from typing import Optional

from ailment import Expr

from angr.engines.vex.claripy.ccall import data
from .rewriter_base import CCallRewriterBase


AMD64_CondTypes = data['AMD64']['CondTypes']
AMD64_OpTypes = data['AMD64']['OpTypes']
AMD64_CondBitMasks = data['AMD64']['CondBitMasks']
AMD64_CondBitOffsets = data['AMD64']['CondBitOffsets']


class AMD64CCallRewriter(CCallRewriterBase):
    """
    Implements ccall rewriter for AMD64.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Optional[Expr.Expression]:
        if ccall.cee_name == "amd64g_calculate_condition":
            cond = ccall.operands[0]
            op = ccall.operands[1]
            dep_1 = ccall.operands[2]
            dep_2 = ccall.operands[3]
            if isinstance(cond, Expr.Const) and isinstance(op, Expr.Const):
                cond_v = cond.value
                op_v = op.value
                if cond_v == AMD64_CondTypes['CondLE']:
                    if op_v in {AMD64_OpTypes['G_CC_OP_SUBB'], AMD64_OpTypes['G_CC_OP_SUBW'],
                                AMD64_OpTypes['G_CC_OP_SUBL'], AMD64_OpTypes['G_CC_OP_SUBQ']}:
                        # dep_1 <=s dep_2
                        r = Expr.BinaryOp(ccall.idx, "CmpLE",
                                          (dep_1, dep_2),
                                          True,
                                          **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                if cond_v == AMD64_CondTypes['CondZ']:
                    if op_v in {AMD64_OpTypes['G_CC_OP_SUBB'], AMD64_OpTypes['G_CC_OP_SUBW'],
                                AMD64_OpTypes['G_CC_OP_SUBL'], AMD64_OpTypes['G_CC_OP_SUBQ']}:
                        # dep_1 - dep_2 == 0
                        r = Expr.BinaryOp(ccall.idx, "CmpEQ",
                                          (dep_1, dep_2),
                                          False,
                                          **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes['CondL']:
                    if op_v in {AMD64_OpTypes['G_CC_OP_SUBB'], AMD64_OpTypes['G_CC_OP_SUBW'],
                                AMD64_OpTypes['G_CC_OP_SUBL'], AMD64_OpTypes['G_CC_OP_SUBQ']}:
                        # dep_1 - dep_2 <s 0
                        r = Expr.BinaryOp(ccall.idx, "CmpLT",
                                          (dep_1, dep_2),
                                          True,
                                          **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes['CondNBE']:
                    if op_v in {AMD64_OpTypes['G_CC_OP_SUBB'], AMD64_OpTypes['G_CC_OP_SUBW'],
                                AMD64_OpTypes['G_CC_OP_SUBL'], AMD64_OpTypes['G_CC_OP_SUBQ']}:
                        # dep_1 - dep_2 > 0
                        r = Expr.BinaryOp(ccall.idx, "CmpGT",
                                          (dep_1, dep_2),
                                          False,
                                          **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

        elif ccall.cee_name == "amd64g_calculate_rflags_c":
            # calculate the carry flag
            op = ccall.operands[0]
            dep_1 = ccall.operands[1]
            dep_2 = ccall.operands[2]
            ndep = ccall.operands[3]
            if isinstance(op, Expr.Const):
                op_v = op.value
                if op_v in {AMD64_OpTypes['G_CC_OP_ADDB'], AMD64_OpTypes['G_CC_OP_ADDW'],
                            AMD64_OpTypes['G_CC_OP_ADDL'], AMD64_OpTypes['G_CC_OP_ADDQ']}:
                    # pc_actions_ADD
                    cf = Expr.ITE(None,
                                  Expr.BinaryOp(None,
                                                "CmpLE",
                                                [
                                                    Expr.BinaryOp(None, "Add", [dep_1, dep_2], False),
                                                    dep_1,
                                                ],
                                                False,
                                                ),
                                  Expr.Const(None, None, 0, ccall.bits),
                                  Expr.Const(None, None, 1, ccall.bits),
                                  **ccall.tags)
                    return cf

                if op_v in {AMD64_OpTypes['G_CC_OP_SUBB'], AMD64_OpTypes['G_CC_OP_SUBW'],
                            AMD64_OpTypes['G_CC_OP_SUBL'], AMD64_OpTypes['G_CC_OP_SUBQ']}:
                    # pc_actions_SUB
                    cf = Expr.BinaryOp(None, "CmpLT", [dep_1,dep_2,], False)
                    if cf.bits == ccall.bits:
                        return cf
                    return Expr.Convert(None, cf.bits, ccall.bits, False, cf, **ccall.tags)

                if op_v in {AMD64_OpTypes['G_CC_OP_DECB'], AMD64_OpTypes['G_CC_OP_DECW'],
                            AMD64_OpTypes['G_CC_OP_DECL'], AMD64_OpTypes['G_CC_OP_DECQ']}:
                    # pc_actions_DEC
                    cf = Expr.BinaryOp(
                        None,
                        "Shr",
                        [
                            Expr.BinaryOp(None, "And", [ndep,
                                                        Expr.Const(None, None, AMD64_CondBitMasks['G_CC_MASK_C'], 64)
                                                        ],
                                          False),
                            Expr.Const(None, None, AMD64_CondBitOffsets['G_CC_SHIFT_C'], 64),
                        ],
                        False,
                        **ccall.tags)
                    return cf

        return None

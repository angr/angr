from __future__ import annotations

from .a_div_const_add_a_mul_n_div_const import ADivConstAddAMulNDivConst
from .a_mul_const_div_shr_const import AMulConstDivShrConst
from .a_shl_const_sub_a import AShlConstSubA
from .a_sub_a_div import ASubADiv
from .a_sub_a_div_const_mul_const import ASubADivConstMulConst
from .a_sub_a_shr_const_shr_const import ASubAShrConstShrConst
from .arm_cmpf import ARMCmpF
from .bswap import Bswap
from .cas_intrinsics import CASIntrinsics
from .coalesce_same_cascading_ifs import CoalesceSameCascadingIfs
from .constant_derefs import ConstantDereferences
from .const_mull_a_shift import ConstMullAShift
from .extended_byte_and_mask import ExtendedByteAndMask
from .remove_empty_if_body import RemoveEmptyIfBody
from .remove_redundant_ite_branch import RemoveRedundantITEBranches
from .shl_to_mul import ShlToMul
from .single_bit_xor import SingleBitXor
from .a_sub_a_sub_n import ASubASubN
from .conv_a_sub0_shr_and import ConvASub0ShrAnd
from .eager_eval import EagerEvaluation
from .one_sub_bool import OneSubBool
from .bool_expr_xor_1 import BoolExprXor1
from .bitwise_or_to_logical_or import BitwiseOrToLogicalOr
from .remove_redundant_bitmasks import RemoveRedundantBitmasks
from .remove_redundant_nots import RemoveRedundantNots
from .remove_redundant_reinterprets import RemoveRedundantReinterprets
from .remove_redundant_shifts import RemoveRedundantShifts
from .remove_redundant_shifts_around_comparators import RemoveRedundantShiftsAroundComparators
from .simplify_pc_relative_loads import SimplifyPcRelativeLoads
from .basepointeroffset_add_n import BasePointerOffsetAddN
from .basepointeroffset_and_mask import BasePointerOffsetAndMask
from .remove_redundant_conversions import RemoveRedundantConversions
from .remove_cascading_conversions import RemoveCascadingConversions
from .conv_shl_shr import ConvShlShr
from .rewrite_mips_gp_loads import RewriteMipsGpLoads
from .remove_noop_conversions import RemoveNoopConversions
from .rewrite_bit_extractions import RewriteBitExtractions
from .remove_redundant_ite_comparisons import RemoveRedundantITEComparisons
from .single_bit_cond_to_boolexpr import SingleBitCondToBoolExpr
from .sar_to_signed_div import SarToSignedDiv
from .tidy_stack_addr import TidyStackAddr
from .invert_negated_logical_conjuction_disjunction import InvertNegatedLogicalConjunctionsAndDisjunctions
from .rol_ror import RolRorRewriter
from .inlined_strcpy import InlinedStrcpy
from .inlined_strcpy_consolidation import InlinedStrcpyConsolidation
from .inlined_wstrcpy import InlinedWstrcpy
from .cmpord_rewriter import CmpORDRewriter
from .coalesce_adjacent_shrs import CoalesceAdjacentShiftRights
from .a_mul_const_sub_a import AMulConstSubA
from .rewrite_cxx_operator_calls import RewriteCxxOperatorCalls
from .remove_cxx_destructor_calls import RemoveCxxDestructorCalls
from .rewrite_conv_mul import RewriteConvMul
from .base import PeepholeOptimizationExprBase, PeepholeOptimizationStmtBase, PeepholeOptimizationMultiStmtBase


ALL_PEEPHOLE_OPTS: list[type[PeepholeOptimizationExprBase]] = [
    ADivConstAddAMulNDivConst,
    AMulConstDivShrConst,
    AShlConstSubA,
    AMulConstSubA,
    ASubADiv,
    ASubADivConstMulConst,
    ASubAShrConstShrConst,
    ARMCmpF,
    Bswap,
    CASIntrinsics,
    CoalesceSameCascadingIfs,
    ConstantDereferences,
    ConstMullAShift,
    ExtendedByteAndMask,
    RemoveEmptyIfBody,
    RemoveRedundantITEBranches,
    SingleBitXor,
    ASubASubN,
    ConvASub0ShrAnd,
    EagerEvaluation,
    OneSubBool,
    BoolExprXor1,
    BitwiseOrToLogicalOr,
    RemoveRedundantBitmasks,
    RemoveRedundantNots,
    RemoveRedundantReinterprets,
    RemoveRedundantShifts,
    RemoveRedundantShiftsAroundComparators,
    SimplifyPcRelativeLoads,
    BasePointerOffsetAddN,
    BasePointerOffsetAndMask,
    RemoveRedundantConversions,
    RemoveCascadingConversions,
    ConvShlShr,
    RewriteMipsGpLoads,
    RemoveNoopConversions,
    RewriteBitExtractions,
    RemoveRedundantITEComparisons,
    SingleBitCondToBoolExpr,
    SarToSignedDiv,
    TidyStackAddr,
    InvertNegatedLogicalConjunctionsAndDisjunctions,
    RolRorRewriter,
    InlinedStrcpy,
    InlinedStrcpyConsolidation,
    InlinedWstrcpy,
    CmpORDRewriter,
    CoalesceAdjacentShiftRights,
    ShlToMul,
    RewriteCxxOperatorCalls,
    RemoveCxxDestructorCalls,
    RewriteConvMul,
]

MULTI_STMT_OPTS: list[type[PeepholeOptimizationMultiStmtBase]] = [
    v for v in ALL_PEEPHOLE_OPTS if issubclass(v, PeepholeOptimizationMultiStmtBase)
]
STMT_OPTS: list[type[PeepholeOptimizationStmtBase]] = [
    v for v in ALL_PEEPHOLE_OPTS if issubclass(v, PeepholeOptimizationStmtBase)
]
EXPR_OPTS: list[type[PeepholeOptimizationExprBase]] = [
    v for v in ALL_PEEPHOLE_OPTS if issubclass(v, PeepholeOptimizationExprBase)
]

__all__ = (
    "EXPR_OPTS",
    "MULTI_STMT_OPTS",
    "STMT_OPTS",
)

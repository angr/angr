from __future__ import annotations

from typing import Any

from .a_div_const_add_a_mul_n_div_const import ADivConstAddAMulNDivConst
from .a_mul_const_div_shr_const import AMulConstDivShrConst
from .a_mul_const_sub_a import AMulConstSubA
from .a_shl_const_sub_a import AShlConstSubA
from .a_sub_a_div import ASubADiv
from .a_sub_a_shr_const_shr_const import ASubAShrConstShrConst
from .a_sub_a_sub_n import ASubASubN
from .arm_cmpf import ARMCmpF
from .base import PeepholeOptimizationExprBase, PeepholeOptimizationMultiStmtBase, PeepholeOptimizationStmtBase
from .basepointeroffset_add_n import BasePointerOffsetAddN
from .basepointeroffset_and_mask import BasePointerOffsetAndMask
from .bitwise_inserts import SimplifyBitwiseInserts
from .bitwise_or_to_logical_or import BitwiseOrToLogicalOr
from .bool_expr_xor_1 import BoolExprXor1
from .bswap import Bswap
from .bt_rflags_merge import BTRflagsMergeBitExtraction
from .cas_intrinsics import CASIntrinsics
from .cmp_masked_shift import CmpMaskedShift
from .cmp_sub_const import CmpSubConst
from .cmpf_flag_tests import CmpFFlagTests
from .cmpord_rewriter import CmpORDRewriter
from .coalesce_adjacent_shrs import CoalesceAdjacentShiftRights
from .coalesce_same_cascading_ifs import CoalesceSameCascadingIfs
from .concat_simplifier import ConcatSimplifier
from .constant_derefs import ConstantDereferences
from .conv_a_sub0_shr_and import ConvASub0ShrAnd
from .conv_shl_shr import ConvShlShr
from .eager_eval import EagerEvaluation
from .evaluate_const_conversions import EvaluateConstConversions
from .extended_byte_and_mask import ExtendedByteAndMask
from .float_const_bits import FloatConstBits
from .fp_exact_identities import FPExactIdentities
from .invert_negated_logical_conjuction_disjunction import InvertNegatedLogicalConjunctionsAndDisjunctions
from .known_pattern_call_info import KnownPatternCallInfo
from .magic_div_simplifier import MagicDivisionSimplifier
from .masked_insert import SimplifyMaskedInsert
from .modulo_simplifier import ModuloSimplifier
from .narrow_fp_ops import NarrowFPOperations
from .one_sub_bool import OneSubBool
from .optimized_div_simplifier import OptimizedDivisionSimplifier
from .recombine_split_halves import RecombineSplitHalves
from .remove_cascading_conversions import RemoveCascadingConversions
from .remove_const_insert import RemoveConstInsert
from .remove_cxx_destructor_calls import RemoveCxxDestructorCalls
from .remove_empty_if_body import RemoveEmptyIfBody
from .remove_fptag_nan_ite import RemoveFptagNanITE
from .remove_int_fp_int_roundtrip import RemoveIntFPIntRoundTrip
from .remove_noop_conversions import RemoveNoopConversions
from .remove_redundant_bitmasks import RemoveRedundantBitmasks
from .remove_redundant_conversions import RemoveRedundantConversions
from .remove_redundant_derefs import RemoveRedundantDerefs
from .remove_redundant_insert import RemoveRedundantInsert
from .remove_redundant_ite_branch import RemoveRedundantITEBranches
from .remove_redundant_ite_comparisons import RemoveRedundantITEComparisons
from .remove_redundant_nots import RemoveRedundantNots
from .remove_redundant_reinterprets import RemoveRedundantReinterprets
from .remove_redundant_shifts import RemoveRedundantShifts
from .remove_redundant_shifts_around_comparators import RemoveRedundantShiftsAroundComparators
from .remove_reinterprets_at_stores import RemoveReinterpretsAtStores
from .rewrite_bit_extractions import RewriteBitExtractions
from .rewrite_conv_mul import RewriteConvMul
from .rewrite_cxx_operator_calls import RewriteCxxOperatorCalls
from .rewrite_mips_gp_loads import RewriteMipsGpLoads
from .rol_ror import RolRorRewriter
from .sar_to_signed_div import SarToSignedDiv
from .sbb_mask_to_ite import SbbMaskToITE
from .shl_to_mul import ShlToMul
from .sign_bit_test import SignBitTest
from .simplify_pc_relative_loads import SimplifyPcRelativeLoads
from .single_bit_cond_to_boolexpr import SingleBitCondToBoolExpr
from .single_bit_xor import SingleBitXor
from .sse_bitwise_select import SSEBitwiseSelect
from .sse_movemask import SSEMoveMask
from .sse_scalar_lowering import SSEScalarLowering, SSEVectorConvertLowering
from .sse_vector_lane_lowering import SSEVectorLaneLowering
from .tidy_stack_addr import TidyStackAddr
from .x87_cmpf import X87CmpF
from .x87_narrowing_store import X87NarrowingStore

ALL_PEEPHOLE_OPTS: list[Any] = [
    RemoveFptagNanITE,
    ADivConstAddAMulNDivConst,
    AMulConstDivShrConst,
    AShlConstSubA,
    AMulConstSubA,
    ASubADiv,
    ModuloSimplifier,
    ASubAShrConstShrConst,
    ARMCmpF,
    X87CmpF,
    Bswap,
    BTRflagsMergeBitExtraction,
    CASIntrinsics,
    CoalesceSameCascadingIfs,
    ConcatSimplifier,
    ConstantDereferences,
    MagicDivisionSimplifier,
    OptimizedDivisionSimplifier,
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
    RemoveConstInsert,
    RemoveRedundantBitmasks,
    RemoveRedundantDerefs,
    RemoveRedundantNots,
    RemoveRedundantReinterprets,
    RemoveReinterpretsAtStores,
    FloatConstBits,
    RemoveRedundantShifts,
    RemoveRedundantShiftsAroundComparators,
    SimplifyBitwiseInserts,
    SimplifyMaskedInsert,
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
    SignBitTest,
    SingleBitCondToBoolExpr,
    SarToSignedDiv,
    TidyStackAddr,
    InvertNegatedLogicalConjunctionsAndDisjunctions,
    RolRorRewriter,
    CmpFFlagTests,
    CmpORDRewriter,
    CmpMaskedShift,
    CmpSubConst,
    CoalesceAdjacentShiftRights,
    ShlToMul,
    RecombineSplitHalves,
    RewriteCxxOperatorCalls,
    RemoveCxxDestructorCalls,
    KnownPatternCallInfo,
    RewriteConvMul,
    EvaluateConstConversions,
    RemoveRedundantInsert,
    RemoveIntFPIntRoundTrip,
    X87NarrowingStore,
    NarrowFPOperations,
    FPExactIdentities,
    SSEScalarLowering,
    SSEVectorConvertLowering,
    SSEVectorLaneLowering,
    SSEBitwiseSelect,
    SSEMoveMask,
    SbbMaskToITE,
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

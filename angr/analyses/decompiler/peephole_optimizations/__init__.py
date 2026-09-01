from __future__ import annotations

from typing import Any

from .a_div_const_add_a_mul_n_div_const import ADivConstAddAMulNDivConst
from .a_div_mod_divisor_size import DivModDivisorSize
from .a_mul_const_div_shr_const import AMulConstDivShrConst
from .a_mul_const_sub_a import AMulConstSubA
from .a_shl_const_sub_a import AShlConstSubA
from .a_sub_a_div import ASubADiv
from .a_sub_a_shr_const_shr_const import ASubAShrConstShrConst
from .a_sub_a_sub_n import ASubASubN
from .a_two_sub_to_add import TwoSubToAdd
from .and_mask_pruning import AndMaskPruning
from .arm_cmpf import ARMCmpF
from .base import PeepholeOptimizationExprBase, PeepholeOptimizationMultiStmtBase, PeepholeOptimizationStmtBase
from .basepointeroffset_add_n import BasePointerOffsetAddN
from .basepointeroffset_and_mask import BasePointerOffsetAndMask
from .binary_op_canonicalization import BinaryOpCanonicalization
from .bitwise_inserts import SimplifyBitwiseInserts
from .bitwise_or_to_logical_or import BitwiseOrToLogicalOr
from .bool_expr_xor_1 import BoolExprXor1
from .bswap import Bswap
from .cas_intrinsics import CASIntrinsics
from .cmp_masked_shift import CmpMaskedShift
from .cmp_sub_const import CmpSubConst
from .cmpord_rewriter import CmpORDRewriter
from .coalesce_adjacent_shrs import CoalesceAdjacentShiftRights
from .coalesce_same_cascading_ifs import CoalesceSameCascadingIfs
from .concat_simplifier import ConcatSimplifier
from .constant_derefs import ConstantDereferences
from .conv_a_sub0_shr_and import ConvASub0ShrAnd
from .conv_load_64_to_32 import ConvLoad
from .conv_shl_shr import ConvShlShr
from .eager_eval import EagerEvaluation
from .evaluate_const_conversions import EvaluateConstConversions
from .extended_byte_and_mask import ExtendedByteAndMask
from .invert_negated_logical_conjuction_disjunction import InvertNegatedLogicalConjunctionsAndDisjunctions
from .modulo_simplifier import ModuloSimplifier
from .one_sub_bool import OneSubBool
from .optimized_div_simplifier import OptimizedDivisionSimplifier
from .remove_cascading_conversions import RemoveCascadingConversions
from .remove_const_insert import RemoveConstInsert
from .remove_cxx_destructor_calls import RemoveCxxDestructorCalls
from .remove_empty_if_body import RemoveEmptyIfBody
from .remove_id_ac_d_flags import RemoveIdFlag
from .remove_noop_conversions import RemoveNoopConversions
from .remove_redundant_bitmasks import RemoveRedundantBitmasks
from .remove_redundant_conditional_jump import RemoveRedunCondJump
from .remove_redundant_and import RemoveRedundantAnds
from .remove_redundant_conversions import RemoveRedundantConversions
from .remove_redundant_derefs import RemoveRedundantDerefs
from .remove_redundant_insert import RemoveRedundantInsert
from .remove_redundant_ite import RedundantITE
from .remove_redundant_ite_branch import RemoveRedundantITEBranches
from .remove_redundant_ite_comparisons import RemoveRedundantITEComparisons
from .remove_redundant_negations import RemoveRedundantNegations
from .remove_redundant_nots import RemoveRedundantNots
from .remove_redundant_reinterprets import RemoveRedundantReinterprets
from .remove_redundant_shifts import RemoveRedundantShifts
from .remove_redundant_shifts_around_comparators import RemoveRedundantShiftsAroundComparators
from .remove_unused_ndep import RemoveUnusedNdeps
from .rewrite_bit_extractions import RewriteBitExtractions
from .rewrite_constant_offset_loads import RewriteConstantOffsetLoads
from .rewrite_conv_mul import RewriteConvMul
from .rewrite_cxx_operator_calls import RewriteCxxOperatorCalls
from .rewrite_mips_gp_loads import RewriteMipsGpLoads
from .rol_ror import RolRorRewriter
from .sar_to_signed_div import SarToSignedDiv
from .shl_to_mul import ShlToMul
from .simplify_pc_relative_loads import SimplifyPcRelativeLoads
from .single_bit_cond_to_boolexpr import SingleBitCondToBoolExpr
from .single_bit_xor import SingleBitXor
from .tidy_stack_addr import TidyStackAddr
from .vm_protect_sub_as_not import VMPSubAsNot
from .xor_simplifications import XorSimplifications

ALL_PEEPHOLE_OPTS: list[Any] = [
    ADivConstAddAMulNDivConst,
    AMulConstDivShrConst,
    AShlConstSubA,
    AMulConstSubA,
    ASubADiv,
    ModuloSimplifier,
    ASubAShrConstShrConst,
    AndMaskPruning,
    ARMCmpF,
    Bswap,
    CASIntrinsics,
    CoalesceSameCascadingIfs,
    ConcatSimplifier,
    ConstantDereferences,
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
    RemoveRedundantShifts,
    RemoveRedundantShiftsAroundComparators,
    SimplifyBitwiseInserts,
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
    CmpORDRewriter,
    CmpMaskedShift,
    CmpSubConst,
    CoalesceAdjacentShiftRights,
    ShlToMul,
    RewriteCxxOperatorCalls,
    RemoveCxxDestructorCalls,
    RewriteConvMul,
    EvaluateConstConversions,
    RemoveRedundantInsert,
    RemoveRedundantAnds,
    BinaryOpCanonicalization,
    ConvLoad,
    DivModDivisorSize,
    RedundantITE,
    RemoveIdFlag,
    RemoveRedunCondJump,
    RemoveRedundantNegations,
    RemoveUnusedNdeps,
    RewriteConstantOffsetLoads,
    TwoSubToAdd,
    VMPSubAsNot,
    XorSimplifications,
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

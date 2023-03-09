from typing import List, Type

from .a_div_const_add_a_mul_n_div_const import ADivConstAddAMulNDivConst
from .a_mul_const_div_shr_const import AMulConstDivShrConst
from .a_shl_const_sub_a import AShlConstSubA
from .a_sub_a_div import ASubADiv
from .a_sub_a_div_const_mul_const import ASubADivConstMulConst
from .a_sub_a_sub_n import ASubASubN
from .arm_cmpf import ARMCmpF
from .base import PeepholeOptimizationExprBase, PeepholeOptimizationStmtBase
from .basepointeroffset_add_n import BasePointerOffsetAddN
from .basepointeroffset_and_mask import BasePointerOffsetAndMask
from .bitwise_or_to_logical_or import BitwiseOrToLogicalOr
from .bool_expr_xor_1 import BoolExprXor1
from .bswap import Bswap
from .coalesce_same_cascading_ifs import CoalesceSameCascadingIfs
from .constant_derefs import ConstantDereferences
from .conv_a_sub0_shr_and import ConvASub0ShrAnd
from .conv_const_mull_a_shift import ConvConstMullAShift
from .conv_shl_shr import ConvShlShr
from .eager_eval import EagerEvaluation
from .extended_byte_and_mask import ExtendedByteAndMask
from .one_sub_bool import OneSubBool
from .remove_cascading_conversions import RemoveCascadingConversions
from .remove_empty_if_body import RemoveEmptyIfBody
from .remove_noop_conversions import RemoveNoopConversions
from .remove_redundant_bitmasks import RemoveRedundantBitmasks
from .remove_redundant_conversions import RemoveRedundantConversions
from .remove_redundant_ite_branch import RemoveRedundantITEBranches
from .remove_redundant_nots import RemoveRedundantNots
from .remove_redundant_reinterprets import RemoveRedundantReinterprets
from .remove_redundant_shifts import RemoveRedundantShifts
from .remove_redundant_shifts_around_comparators import RemoveRedundantShiftsAroundComparators
from .rewrite_mips_gp_loads import RewriteMipsGpLoads
from .rewrite_bit_extractions import RewriteBitExtractions
from .remove_redundant_ite_comparisons import RemoveRedundantITEComparisons

from .simplify_pc_relative_loads import SimplifyPcRelativeLoads
from .single_bit_xor import SingleBitXor

STMT_OPTS: List[Type[PeepholeOptimizationStmtBase]] = []
EXPR_OPTS: List[Type[PeepholeOptimizationExprBase]] = []

_g = globals().copy()
for v in _g.values():
    if isinstance(v, type) and issubclass(v, PeepholeOptimizationExprBase) and v is not PeepholeOptimizationExprBase:
        EXPR_OPTS.append(v)

    if isinstance(v, type) and issubclass(v, PeepholeOptimizationStmtBase) and v is not PeepholeOptimizationStmtBase:
        STMT_OPTS.append(v)

_g = None

from typing import List, Type

from .coalesce_same_cascading_ifs import CoalesceSameCascadingIfs
from .constant_derefs import ConstantDereferences
from .extended_byte_and_mask import ExtendedByteAndMask
from .remove_empty_if_body import RemoveEmptyIfBody
from .remove_redundant_ite_branch import RemoveRedundantITEBranches
from .single_bit_xor import SingleBitXor
from .a_sub_a_sub_n import ASubASubN
from .conv_a_sub0_shr_and import ConvASub0ShrAnd
from .eager_eval import EagerEvaluation
from .one_sub_bool import OneSubBool
from .bool_expr_xor_1 import BoolExprXor1
from .remove_redundant_bitmasks import RemoveRedundantBitmasks
from .remove_redundant_nots import RemoveRedundantNots
from .remove_redundant_shifts import RemoveRedundantShifts
from .simplify_pc_relative_loads import SimplifyPcRelativeLoads
from .basepointeroffset_add_n import BasePointerOffsetAddN
from .basepointeroffset_and_mask import BasePointerOffsetAndMask
from .remove_redundant_conversions import RemoveRedundantConversions
from .remove_cascading_conversions import RemoveCascadingConversions
from .conv_shl_shr import ConvShlShr
from .rewrite_mips_gp_loads import RewriteMipsGpLoads

from .base import PeepholeOptimizationExprBase, PeepholeOptimizationStmtBase


STMT_OPTS: List[Type[PeepholeOptimizationStmtBase]] = []
EXPR_OPTS: List[Type[PeepholeOptimizationExprBase]] = []

_g = globals().copy()
for v in _g.values():
    if (isinstance(v, type)
        and issubclass(v, PeepholeOptimizationExprBase)
        and v is not PeepholeOptimizationExprBase
    ):
        EXPR_OPTS.append(v)

    if (isinstance(v, type)
        and issubclass(v, PeepholeOptimizationStmtBase)
        and v is not PeepholeOptimizationStmtBase
    ):
        STMT_OPTS.append(v)

_g = None

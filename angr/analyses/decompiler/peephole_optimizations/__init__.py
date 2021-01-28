from .coalesce_same_cascading_ifs import CoalesceSameCascadingIfs
from .constant_derefs import ConstantDereferences
from .remove_empty_if_body import RemoveEmptyIfBody
from .single_bit_xor import SingleBitXor
from .a_sub_a_sub_n import ASubASubN
from .conv_a_sub0_shr_and import ConvASub0ShrAnd
from .one_sub_bool import OneSubBool
from .bool_expr_xor_1 import BoolExprXor1
from .remove_redundant_bitmasks import RemoveRedundantBitmasks
from .remove_redundant_nots import RemoveRedundantNots
from .remove_redundant_shifts import RemoveRedundantShifts
from .conv_shl_shr import ConvShlShr

from .base import PeepholeOptimizationExprBase, PeepholeOptimizationStmtBase


STMT_OPTS = [ ]
EXPR_OPTS = [ ]

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

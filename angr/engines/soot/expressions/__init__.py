import logging

l = logging.getLogger("angr.engines.soot.expressions")


def translate_expr(expr, state):
    expr_name = expr.__class__.__name__.split(".")[-1]
    if expr_name.startswith("Soot"):
        expr_name = expr_name[4:]
    if expr_name.endswith("Expr"):
        expr_name = expr_name[:-4]
    expr_cls_name = "SimSootExpr_" + expr_name

    g = globals()
    if expr_cls_name in g:
        expr_cls = g[expr_cls_name]
    else:
        l.warning("Unsupported Soot expression %s.", expr_cls_name)
        expr_cls = SimSootExpr_Unsupported

    expr = expr_cls(expr, state)
    expr.process()
    return expr


from .arrayref import SimSootExpr_ArrayRef
from .binop import SimSootExpr_Binop
from .cast import SimSootExpr_Cast
from .condition import SimSootExpr_Condition
from .constants import (
    SimSootExpr_IntConstant,
    SimSootExpr_LongConstant,
    SimSootExpr_FloatConstant,
    SimSootExpr_DoubleConstant,
    SimSootExpr_StringConstant,
    SimSootExpr_ClassConstant,
    SimSootExpr_NullConstant,
)
from .instancefieldref import SimSootExpr_InstanceFieldRef
from .invoke import (
    SimSootExpr_SpecialInvoke,
    SimSootExpr_StaticInvoke,
    SimSootExpr_VirtualInvoke,
    SimSootExpr_InterfaceInvoke,
)
from .length import SimSootExpr_Length
from .local import SimSootExpr_Local
from .new import SimSootExpr_New
from .newArray import SimSootExpr_NewArray
from .newMultiArray import SimSootExpr_NewMultiArray
from .phi import SimSootExpr_Phi
from .staticfieldref import SimSootExpr_StaticFieldRef
from .thisref import SimSootExpr_ThisRef
from .paramref import SimSootExpr_ParamRef
from .unsupported import SimSootExpr_Unsupported
from .instanceOf import SimSootExpr_InstanceOf

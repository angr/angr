
import logging
l = logging.getLogger('angr.engines.soot.expressions')


def translate_expr(expr, state):
    expr_name = expr.__class__.__name__.split('.')[-1]
    if expr_name.startswith('Soot'): expr_name = expr_name[4:]
    if expr_name.endswith("Expr"): expr_name = expr_name[:-4]
    expr_cls_name = 'SimSootExpr_' + expr_name

    g = globals()
    if expr_cls_name in g:
        expr_cls = g[expr_cls_name]
    else:
        l.warning('Unsupported Soot expression %s.', expr_cls_name)
        expr_cls = SimSootExpr_Unsupported

    expr = expr_cls(expr, state)
    expr.process()
    return expr


from .new import SimSootExpr_New
from .local import SimSootExpr_Local
from .virtualinvoke import SimSootExpr_VirtualInvoke
from .staticinvoke import SimSootExpr_StaticInvoke
from .binop import SimSootExpr_Binop
from .condition import SimSootExpr_Condition
from .paramref import SimSootExpr_ParamRef
from .phi import SimSootExpr_Phi
from .unsupported import SimSootExpr_Unsupported
from .constants import *

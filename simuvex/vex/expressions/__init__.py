def translate_expr(expr, imark, stmt_idx, state):
    expr_name = 'SimIRExpr_' + type(expr).__name__.split('IRExpr')[-1].split('.')[-1]
    g = globals()

    if expr_name not in g and o.BYPASS_UNSUPPORTED_IREXPR not in state.options:
        raise UnsupportedIRExprError("Unsupported expression type %s" % (type(expr)))
    elif expr_name not in g:
        expr_class = SimIRExpr_Unsupported
    else:
        expr_class = g[expr_name]

    l.debug("Processing expression %s", expr_name)
    e = expr_class(expr, imark, stmt_idx, state)
    e.process()
    return e

from ...s_errors import UnsupportedIRExprError
from ... import s_options as o

import logging
l = logging.getLogger('simuvex.vex.expressions')

from .base import SimIRExpr

from .bbptr import SimIRExpr_BBPTR
from .vecret import SimIRExpr_VECRET
from .rdtmp import SimIRExpr_RdTmp
from .get import SimIRExpr_Get
from .load import SimIRExpr_Load
from .op import SimIRExpr_Unop, SimIRExpr_Binop, SimIRExpr_Triop, SimIRExpr_Qop
from .const import SimIRExpr_Const
from .ccall import SimIRExpr_CCall
from .ite import SimIRExpr_ITE
from .geti import SimIRExpr_GetI
from .unsupported import SimIRExpr_Unsupported

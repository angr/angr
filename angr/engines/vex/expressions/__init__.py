def translate_expr(expr, state):
    expr_class = EXPR_CLASSES.get(type(expr), None)
    if expr_class is None:
        if o.BYPASS_UNSUPPORTED_IREXPR not in state.options:
            raise UnsupportedIRExprError("Unsupported expression type %s" % (type(expr)))
        else:
            expr_class = SimIRExpr_Unsupported

    # l.debug("Processing expression %s", expr_name)
    e = expr_class(expr, state)
    e.process()
    return e

from ....errors import UnsupportedIRExprError
from .... import sim_options as o

import logging
l = logging.getLogger(name=__name__)

import pyvex

from .base import SimIRExpr

from .gsptr import SimIRExpr_GSPTR
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

EXPR_CLASSES = {
    pyvex.expr.GSPTR: SimIRExpr_GSPTR,
    pyvex.expr.VECRET: SimIRExpr_VECRET,
    pyvex.expr.Const: SimIRExpr_Const,
    pyvex.expr.RdTmp: SimIRExpr_RdTmp,
    pyvex.expr.Get: SimIRExpr_Get,
    pyvex.expr.Load: SimIRExpr_Load,
    pyvex.expr.Unop: SimIRExpr_Unop,
    pyvex.expr.Binop: SimIRExpr_Binop,
    pyvex.expr.Triop: SimIRExpr_Triop,
    pyvex.expr.Qop: SimIRExpr_Qop,
    pyvex.expr.CCall: SimIRExpr_CCall,
    pyvex.expr.ITE: SimIRExpr_ITE,
    pyvex.expr.GetI:SimIRExpr_GetI,
}

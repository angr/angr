def translate_expr(expr, state):
    try:
        expr_class = EXPR_CLASSES[expr.tag_int]
        if expr_class is None:
            raise IndexError
    except IndexError:
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

EXPR_CLASSES = [None]*pyvex.expr.tag_count

for name, cls in vars(pyvex.expr).items():
    if isinstance(cls, type) and issubclass(cls, pyvex.expr.IRExpr) and cls is not pyvex.expr.IRExpr:
        try:
            EXPR_CLASSES[cls.tag_int] = globals()['SimIRExpr_' + name]
        except KeyError:
            pass

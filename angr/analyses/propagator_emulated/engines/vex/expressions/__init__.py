import pyvex

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

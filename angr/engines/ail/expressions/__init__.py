import ailment

from .sbo import SimIRExpr_StackBaseOffset

EXPR_CLASSES = {
	# ailment.Expr.Atom:              SimIRExpr_Atom,
	# ailment.Expr.Const:             SimIRExpr_Const,
	# ailment.Expr.Tmp:               SimIRExpr_Tmp,
	# ailment.Expr.Register:          SimIRExpr_Register,
	# ailment.Expr.Op:                SimIRExpr_Op,
	# ailment.Expr.UnaryOp:           SimIRExpr_UnaryOp,
	# ailment.Expr.Convert:           SimIRExpr_Convert,
	# ailment.Expr.BinaryOp:          SimIRExpr_BinaryOp,
	# ailment.Expr.Load:              SimIRExpr_Load,
	# ailment.Expr.ITE:               SimIRExpr_ITE,
	# ailment.Expr.DirtyExpression:   SimIRExpr_DirtyExpression,
	# ailment.Expr.BasePointerOffset: SimIRExpr_BasePointerOffset,
	ailment.Expr.StackBaseOffset:   SimIRExpr_StackBaseOffset,
}

# EXPR_CLASSES = [None]*pyvex.expr.tag_count

# for name, cls in vars(pyvex.expr).items():
#     if isinstance(cls, type) and issubclass(cls, pyvex.expr.IRExpr) and cls is not pyvex.expr.IRExpr:
#         try:
#             EXPR_CLASSES[cls.tag_int] = globals()['SimIRExpr_' + name]
#         except KeyError:
#             pass

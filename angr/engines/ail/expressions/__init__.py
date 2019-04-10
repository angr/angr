import ailment

def SimIRExpr_StackBaseOffset(engine, state, expr):
	import ipdb; ipdb.set_trace()

    # ix = engine.handle_expression(state, expr.ix)
    # size_in_bits = get_type_size(expr.descr.elemTy)
    # size = size_in_bits // state.arch.byte_width

    # array_base = expr.descr.base
    # array_index = (ix + expr.bias) % expr.descr.nElems
    # offset = array_base + array_index*size

    # # get it!
    # result = state.registers.load(offset, size)

    # if expr.descr.elemTy.startswith('Ity_F'):
    #     result = result.raw_to_fp()

    # # finish it and save the register references
    # if o.TRACK_REGISTER_ACTIONS in state.options:
    #     r = SimActionData(state, state.registers.id, SimActionData.READ, addr=offset, size=size_in_bits, data=result)
    #     state.history.add_action(r)

    # return result

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

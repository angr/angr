from .CexprParser import CexprParser
from .CexprVisitor import CexprVisitor


def get_original_text(ctx):
    input_stream = ctx.start.getTokenSource().inputStream
    return input_stream.getText(ctx.start.start, ctx.stop.stop)


class C_expr_eval_visitor(CexprVisitor):
    """
    Used by ``angr.c_expr_eval.c_expr_transl()``.
    """
    # pylint: disable=no-else-raise
    def visitPostfixExpr(self, ctx: CexprParser.PostfixExprContext):
        if ctx.Arrow():
            return self.visit(ctx.postfixExpr()) + ".member('" + ctx.Identifier().getText() + "').deref"
        elif ctx.Dot():
            return self.visit(ctx.postfixExpr()) + ".member('" + ctx.Identifier().getText() + "')"
        elif ctx.LeftBracket():
            return self.visit(ctx.postfixExpr()) + ".array(" + self.visit(ctx.expression()) + ")"
        elif ctx.LeftParen():
            return self.visit(ctx.refExpr())
        else:
            return "variable_lookup('" + ctx.Identifier().getText() + "')"

    def visitTypedExpr(self, ctx: CexprParser.TypedExprContext):
        if ctx.typeName():
            return self.visit(ctx.typedExpr()) \
                   + ".with_type(angr.types.parse_type('" + get_original_text(ctx.typeName()) + "'))"
        else:
            return self.visit(ctx.postfixExpr())

    def visitRefExpr(self, ctx: CexprParser.RefExprContext):
        if ctx.And():
            raise NotImplementedError
        elif ctx.Star():
            return self.visit(ctx.refExpr()) + ".deref"
        else:
            return self.visit(ctx.typedExpr())

    def visitBaseExpr(self, ctx: CexprParser.BaseExprContext):
        if ctx.Plus():
            return "+" + self.visit(ctx.baseExpr())
        elif ctx.Minus():
            return "-" + self.visit(ctx.baseExpr())
        elif ctx.Tilde():
            return "~" + self.visit(ctx.baseExpr())
        elif ctx.Not():
            return "claripy.Not(" + self.visit(ctx.baseExpr()) + ")"
        elif ctx.Constant():
            return ctx.Constant().getText()
        elif ctx.StringLiteral():
            return ctx.StringLiteral().getText()
        elif ctx.expression():
            return self.visit(ctx.expression())
        else:
            return self.visit(ctx.refExpr()) + ".resolved"

    def visitMultiplicativeExpr(self, ctx: CexprParser.MultiplicativeExprContext):
        if ctx.Star():
            return "(" + self.visit(ctx.baseExpr()) + " * " + self.visit(ctx.multiplicativeExpr()) + ")"
        elif ctx.Div():
            return "(" + self.visit(ctx.baseExpr()) + " / " + self.visit(ctx.multiplicativeExpr()) + ")"
        elif ctx.Mod():
            return "(" + self.visit(ctx.baseExpr()) + " % " + self.visit(ctx.multiplicativeExpr()) + ")"
        else:
            return self.visit(ctx.baseExpr())

    def visitAdditiveExpr(self, ctx: CexprParser.AdditiveExprContext):
        if ctx.Plus():
            return "(" + self.visit(ctx.multiplicativeExpr()) + " + " + self.visit(ctx.additiveExpr()) + ")"
        elif ctx.Minus():
            return "(" + self.visit(ctx.multiplicativeExpr()) + " - " + self.visit(ctx.additiveExpr()) + ")"
        else:
            return self.visit(ctx.multiplicativeExpr())

    def visitShiftExpr(self, ctx: CexprParser.ShiftExprContext):
        if ctx.LeftShift():
            return "claripy.LShR(" + self.visit(ctx.additiveExpr()) + ", " + self.visit(ctx.shiftExpr()) + ")"
        elif ctx.RightShift():
            return "claripy.RShR(" + self.visit(ctx.additiveExpr()) + ", " + self.visit(ctx.shiftExpr()) + ")"
        else:
            return self.visit(ctx.additiveExpr())

    def visitRelationalExpr(self, ctx: CexprParser.RelationalExprContext):
        # Note: this visitor is type agnostic !!
        # so just treat anything as unsigned ("claripy.Sxx" would make it signed)
        if ctx.Less():
            return "claripy.ULT(" + self.visit(ctx.shiftExpr(0)) + ", " + self.visit(ctx.shiftExpr(1)) + ")"
        elif ctx.LessEqual():
            return "claripy.ULE(" + self.visit(ctx.shiftExpr(0)) + ", " + self.visit(ctx.shiftExpr(1)) + ")"
        elif ctx.GreaterEqual():
            return "claripy.UGE(" + self.visit(ctx.shiftExpr(0)) + ", " + self.visit(ctx.shiftExpr(1)) + ")"
        elif ctx.Greater():
            return "claripy.UGT(" + self.visit(ctx.shiftExpr(0)) + ", " + self.visit(ctx.shiftExpr(1)) + ")"
        else:
            return self.visit(ctx.shiftExpr(0))

    def visitEqualityExpr(self, ctx: CexprParser.EqualityExprContext):
        if ctx.Equal():
            return "(" + self.visit(ctx.relationalExpr()) + " == " + self.visit(ctx.equalityExpr()) + ")"
        elif ctx.NotEqual():
            return "(" + self.visit(ctx.relationalExpr()) + " != " + self.visit(ctx.equalityExpr()) + ")"
        else:
            return self.visit(ctx.relationalExpr())

    def visitBitAndExpr(self, ctx: CexprParser.BitAndExprContext):
        if ctx.And():
            return "(" + self.visit(ctx.equalityExpr()) + " & " + self.visit(ctx.bitAndExpr()) + ")"
        else:
            return self.visit(ctx.equalityExpr())

    def visitBitXorExpr(self, ctx: CexprParser.BitXorExprContext):
        if ctx.Caret():
            return "(" + self.visit(ctx.bitAndExpr()) + " ^ " + self.visit(ctx.bitXorExpr()) + ")"
        else:
            return self.visit(ctx.bitAndExpr())

    def visitBitOrExpr(self, ctx: CexprParser.BitOrExprContext):
        if ctx.Or():
            return "(" + self.visit(ctx.bitXorExpr()) + " | " + self.visit(ctx.bitOrExpr()) + ")"
        else:
            return self.visit(ctx.bitXorExpr())

    def visitLogicalAndExpr(self, ctx: CexprParser.LogicalAndExprContext):
        if ctx.AndAnd():
            return "claripy.And(" + self.visit(ctx.bitOrExpr()) + ", " + self.visit(ctx.logicalAndExpr()) + ")"
        else:
            return self.visit(ctx.bitOrExpr())

    def visitLogicalOrExpr(self, ctx: CexprParser.LogicalOrExprContext):
        if ctx.OrOr():
            return "claripy.Or(" + self.visit(ctx.logicalAndExpr()) + ", " + self.visit(ctx.logicalOrExpr()) + ")"
        else:
            return self.visit(ctx.logicalAndExpr())

    def visitExpression(self, ctx: CexprParser.ExpressionContext):
        if ctx.ifEx:
            return "caripy.If(" + self.visit(ctx.logicalOrExpr()) \
                         + ", " + self.visit(ctx.ifEx) \
                         + ", " + self.visit(ctx.elseEx) + ")"
        else:
            return self.visit(ctx.logicalOrExpr())

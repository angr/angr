# Generated from Cexpr.g4 by ANTLR 4.11.1
from antlr4 import *
if __name__ is not None and "." in __name__:
    from .CexprParser import CexprParser
else:
    from CexprParser import CexprParser

# This class defines a complete generic visitor for a parse tree produced by CexprParser.

class CexprVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by CexprParser#postfixExpr.
    def visitPostfixExpr(self, ctx:CexprParser.PostfixExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#typedExpr.
    def visitTypedExpr(self, ctx:CexprParser.TypedExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#refExpr.
    def visitRefExpr(self, ctx:CexprParser.RefExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#baseExpr.
    def visitBaseExpr(self, ctx:CexprParser.BaseExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#multiplicativeExpr.
    def visitMultiplicativeExpr(self, ctx:CexprParser.MultiplicativeExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#additiveExpr.
    def visitAdditiveExpr(self, ctx:CexprParser.AdditiveExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#shiftExpr.
    def visitShiftExpr(self, ctx:CexprParser.ShiftExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#relationalExpr.
    def visitRelationalExpr(self, ctx:CexprParser.RelationalExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#equalityExpr.
    def visitEqualityExpr(self, ctx:CexprParser.EqualityExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#bitAndExpr.
    def visitBitAndExpr(self, ctx:CexprParser.BitAndExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#bitXorExpr.
    def visitBitXorExpr(self, ctx:CexprParser.BitXorExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#bitOrExpr.
    def visitBitOrExpr(self, ctx:CexprParser.BitOrExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#logicalAndExpr.
    def visitLogicalAndExpr(self, ctx:CexprParser.LogicalAndExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#logicalOrExpr.
    def visitLogicalOrExpr(self, ctx:CexprParser.LogicalOrExprContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#expression.
    def visitExpression(self, ctx:CexprParser.ExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#typeName.
    def visitTypeName(self, ctx:CexprParser.TypeNameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by CexprParser#typePrim.
    def visitTypePrim(self, ctx:CexprParser.TypePrimContext):
        return self.visitChildren(ctx)



del CexprParser
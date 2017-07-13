
import pyvex
from angr.engines.vex.irop import operations as vex_operations

from .block import Block
from .statement import Assignment, Store, DirtyStatement
from .expression import Atom, Const, Register, Tmp, DirtyExpression, BinaryOp


class Converter(object):
    @staticmethod
    def convert(thing):
        raise NotImplementedError()


class VEXExprConverter(Converter):

    @staticmethod
    def from_vex_op(vex_op):
        sim_op = vex_operations[vex_op]
        return sim_op._generic_name

    @staticmethod
    def convert(expr, manager):
        """

        :param expr:
        :return:
        """
        try:
            func = EXPRESSION_MAPPINGS[type(expr)]
        except KeyError:
            return DirtyExpression(manager.next_atom(), expr)

        return func(expr, manager)

    @staticmethod
    def convert_list(exprs, manager):

        converted = [ ]
        for expr in exprs:
            converted.append(VEXExprConverter.convert(expr, manager))
        return converted

    @staticmethod
    def register(offset, bits, manager):
        reg_name = manager.arch.register_names[offset]
        return Register(manager.next_atom(), None, offset, bits, reg_name=reg_name)

    @staticmethod
    def tmp(tmp_idx, bits, manager):
        return Tmp(manager.next_atom(), None, tmp_idx, bits)

    @staticmethod
    def RdTmp(expr, manager):
        return VEXExprConverter.tmp(expr.tmp, expr.result_size(manager.tyenv), manager)

    @staticmethod
    def Get(expr, manager):
        return VEXExprConverter.register(expr.offset, expr.result_size(manager.tyenv), manager)

    @staticmethod
    def Binop(expr, manager):
        return BinaryOp(manager.next_atom(),
                        VEXExprConverter.from_vex_op(expr.op),
                        VEXExprConverter.convert_list(expr.args, manager)
                        )

    @staticmethod
    def Const(expr, manager):
        return Const(manager.next_atom(), None, expr.con.value, expr.result_size(manager.tyenv))


EXPRESSION_MAPPINGS = {
    pyvex.IRExpr.RdTmp: VEXExprConverter.RdTmp,
    pyvex.IRExpr.Get: VEXExprConverter.Get,
    pyvex.IRExpr.Binop: VEXExprConverter.Binop,
    pyvex.IRExpr.Const: VEXExprConverter.Const,
}


class VEXStmtConverter(Converter):

    @staticmethod
    def convert(idx, stmt, manager):
        """

        :param idx:
        :param stmt:
        :param manager:
        :return:
        """

        try:
            func = STATEMENT_MAPPINGS[type(stmt)]
        except KeyError:
            return DirtyStatement(idx, stmt)

        return func(idx, stmt, manager)

    @staticmethod
    def WrTmp(idx, stmt, manager):

        var = VEXExprConverter.tmp(stmt.tmp, stmt.data.result_size(manager.tyenv), manager)
        reg = VEXExprConverter.convert(stmt.data, manager)

        return Assignment(idx, var, reg)

    @staticmethod
    def Put(idx, stmt, manager):
        data = VEXExprConverter.convert(stmt.data, manager)
        reg = VEXExprConverter.register(stmt.offset, data.bits, manager)
        return Assignment(idx, reg, data)

    @staticmethod
    def Store(idx, stmt, manager):

        return Store(idx,
                     VEXExprConverter.convert(stmt.addr, manager),
                     VEXExprConverter.convert(stmt.data, manager)
                     )


STATEMENT_MAPPINGS = {
    pyvex.IRStmt.Put: VEXStmtConverter.Put,
    pyvex.IRStmt.WrTmp: VEXStmtConverter.WrTmp,
    pyvex.IRStmt.Store: VEXStmtConverter.Store,
}


class IRSBConverter(Converter):

    @staticmethod
    def convert(irsb, manager):
        """

        :param irsb:
        :param manager:
        :return:
        """

        # convert each VEX statement into an AIL statement
        statements = [ ]
        idx = 0

        manager.tyenv = irsb.tyenv

        addr = None

        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.IMark):
                if addr is None:
                    addr = stmt.addr + stmt.delta
                continue
            converted = VEXStmtConverter.convert(idx, stmt, manager)
            statements.append(converted)

            idx += 1

        return Block(addr, statements)


import pyvex
from angr.engines.vex.irop import operations as vex_operations

from .block import Block
from .statement import Assignment, Store, Jump, ConditionalJump, Call, DirtyStatement
from .expression import Atom, Const, Register, Tmp, DirtyExpression, UnaryOp, Convert, BinaryOp, Load, ITE


class Converter(object):
    @staticmethod
    def convert(thing):
        raise NotImplementedError()


class VEXExprConverter(Converter):

    @staticmethod
    def generic_name_from_vex_op(vex_op):
        simop = vex_operations[vex_op]
        return simop._generic_name

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
        reg_size = bits // manager.arch.byte_width
        reg_name = manager.arch.translate_register_name(offset, reg_size)
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
    def Load(expr, manager):
        return Load(manager.next_atom(),
                    VEXExprConverter.convert(expr.addr, manager),
                    expr.result_size(manager.tyenv) // 8,
                    expr.end
                    )

    @staticmethod
    def Unop(expr, manager):
        op_name = VEXExprConverter.generic_name_from_vex_op(expr.op)
        if op_name is None:
            # is it a convertion?
            simop = vex_operations[expr.op]
            if simop._conversion:
                return Convert(manager.next_atom(),
                               simop._from_size,
                               simop._to_size,
                               simop.is_signed,
                               VEXExprConverter.convert(expr.args[0], manager),
                               )
            raise NotImplementedError('Unsupported operation')

        return UnaryOp(manager.next_atom(),
                       op_name,
                       VEXExprConverter.convert(expr.args[0], manager),
                       )

    @staticmethod
    def Binop(expr, manager):
        op = VEXExprConverter.generic_name_from_vex_op(expr.op)
        operands = VEXExprConverter.convert_list(expr.args, manager)

        if op == 'Add' and \
                type(operands[1]) is Const and \
                operands[1].sign_bit == 1:
            # convert it to a sub
            op = 'Sub'
            op1_val, op1_bits = operands[1].value, operands[1].bits
            operands[1] = Const(operands[1].idx, None, (1 << op1_bits) - op1_val, op1_bits)

        return BinaryOp(manager.next_atom(),
                        op,
                        operands
                        )

    @staticmethod
    def Const(expr, manager):
        # pyvex.IRExpr.Const
        return Const(manager.next_atom(), None, expr.con.value, expr.result_size(manager.tyenv))

    @staticmethod
    def const_64(expr, manager):
        # pyvex.const.xxx
        return Const(manager.next_atom(), None, expr.value, 64)

    @staticmethod
    def ITE(expr, manager):
        cond = VEXExprConverter.convert(expr.cond, manager)
        iffalse = VEXExprConverter.convert(expr.iffalse, manager)
        iftrue = VEXExprConverter.convert(expr.iftrue, manager)

        return ITE(manager.next_atom(), cond, iffalse, iftrue)


EXPRESSION_MAPPINGS = {
    pyvex.IRExpr.RdTmp: VEXExprConverter.RdTmp,
    pyvex.IRExpr.Get: VEXExprConverter.Get,
    pyvex.IRExpr.Unop: VEXExprConverter.Unop,
    pyvex.IRExpr.Binop: VEXExprConverter.Binop,
    pyvex.IRExpr.Const: VEXExprConverter.Const,
    pyvex.const.U64: VEXExprConverter.const_64,
    pyvex.IRExpr.Load: VEXExprConverter.Load,
    pyvex.IRExpr.ITE: VEXExprConverter.ITE,
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
            return DirtyStatement(idx, stmt, ins_addr=manager.ins_addr)

        return func(idx, stmt, manager)

    @staticmethod
    def WrTmp(idx, stmt, manager):

        var = VEXExprConverter.tmp(stmt.tmp, stmt.data.result_size(manager.tyenv), manager)
        reg = VEXExprConverter.convert(stmt.data, manager)

        return Assignment(idx, var, reg, ins_addr=manager.ins_addr,)

    @staticmethod
    def Put(idx, stmt, manager):
        data = VEXExprConverter.convert(stmt.data, manager)
        reg = VEXExprConverter.register(stmt.offset, data.bits, manager)
        return Assignment(idx, reg, data, ins_addr=manager.ins_addr,)

    @staticmethod
    def Store(idx, stmt, manager):

        return Store(idx,
                     VEXExprConverter.convert(stmt.addr, manager),
                     VEXExprConverter.convert(stmt.data, manager),
                     stmt.data.result_size(manager.tyenv) / 8,
                     ins_addr=manager.ins_addr,
                     )

    @staticmethod
    def Exit(idx, stmt, manager):

        return ConditionalJump(idx,
                               VEXExprConverter.convert(stmt.guard, manager),
                               VEXExprConverter.convert(stmt.dst, manager),
                               None,  # it will be filled in right afterwards
                               ins_addr=manager.ins_addr
                               )


STATEMENT_MAPPINGS = {
    pyvex.IRStmt.Put: VEXStmtConverter.Put,
    pyvex.IRStmt.WrTmp: VEXStmtConverter.WrTmp,
    pyvex.IRStmt.Store: VEXStmtConverter.Store,
    pyvex.IRStmt.Exit: VEXStmtConverter.Exit,
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
            if type(stmt) is pyvex.IRStmt.IMark:
                if addr is None:
                    addr = stmt.addr + stmt.delta
                manager.ins_addr = stmt.addr + stmt.delta
                continue
            elif type(stmt) is pyvex.IRStmt.AbiHint:
                # TODO: How can we use AbiHint?
                continue
            converted = VEXStmtConverter.convert(idx, stmt, manager)
            statements.append(converted)

            idx += 1

        if irsb.jumpkind == 'Ijk_Call':
            # call

            # TODO: is there a conditional call?

            statements.append(Call(manager.next_atom(),
                                   VEXExprConverter.convert(irsb.next, manager),
                                   ins_addr=manager.ins_addr
                                   )
                              )
        elif irsb.jumpkind == 'Ijk_Boring':
            if statements and type(statements[-1]) is ConditionalJump:
                # fill in the false target
                cond_jump = statements[-1]
                cond_jump.false_target = VEXExprConverter.convert(irsb.next, manager)

            else:
                # jump
                statements.append(Jump(manager.next_atom(),
                                       VEXExprConverter.convert(irsb.next, manager),
                                       ins_addr=manager.ins_addr
                                       )
                                  )

        return Block(addr, statements)

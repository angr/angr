import logging

import pyvex
from angr.utils.constants import DEFAULT_STATEMENT
from angr.engines.vex.claripy.irop import vexop_to_simop

from .block import Block
from .statement import Assignment, Store, Jump, Call, ConditionalJump, DirtyStatement, Return
from .expression import Const, Register, Tmp, DirtyExpression, UnaryOp, Convert, BinaryOp, Load, ITE, Reinterpret, \
    VEXCCallExpression
from .converter_common import SkipConversionNotice, Converter


l = logging.getLogger(name=__name__)


class VEXExprConverter(Converter):

    @staticmethod
    def simop_from_vexop(vex_op):
        return vexop_to_simop(vex_op)

    @staticmethod
    def generic_name_from_vex_op(vex_op):
        return vexop_to_simop(vex_op)._generic_name

    @staticmethod
    def convert(expr, manager):  # pylint:disable=arguments-differ
        """

        :param expr:
        :return:
        """
        func = EXPRESSION_MAPPINGS.get(type(expr))
        if func is not None:
            return func(expr, manager)

        if isinstance(expr, pyvex.const.IRConst):
            return VEXExprConverter.const_n(expr, manager)

        if isinstance(expr, pyvex.IRExpr.CCall):
            operands = tuple(VEXExprConverter.convert(arg, manager) for arg in expr.args)
            ccall = VEXCCallExpression(manager.next_atom(), expr.cee.name, operands,
                                       bits=expr.result_size(manager.tyenv))
            return DirtyExpression(manager.next_atom(), ccall, bits=expr.result_size(manager.tyenv))

        l.warning("VEXExprConverter: Unsupported VEX expression of type %s.", type(expr))
        return DirtyExpression(manager.next_atom(), expr, bits=expr.result_size(manager.tyenv))

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
        return Register(manager.next_atom(), None, offset, bits, reg_name=reg_name,
                        ins_addr=manager.ins_addr,
                        vex_block_addr=manager.block_addr,
                        vex_stmt_idx=manager.vex_stmt_idx,
                        )

    @staticmethod
    def tmp(tmp_idx, bits, manager):
        return Tmp(manager.next_atom(), None, tmp_idx, bits,
                   ins_addr=manager.ins_addr,
                   vex_block_addr=manager.block_addr,
                   vex_stmt_idx=manager.vex_stmt_idx,
                   )

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
                    expr.end,
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=manager.vex_stmt_idx,
                    )

    @staticmethod
    def Unop(expr, manager):
        op_name = VEXExprConverter.generic_name_from_vex_op(expr.op)
        if op_name == "Reinterp":
            simop = vexop_to_simop(expr.op)
            return Reinterpret(manager.next_atom(),
                               simop._from_size,
                               simop._from_type,
                               simop._to_size,
                               simop._to_type,
                               VEXExprConverter.convert(expr.args[0], manager),
                               ins_addr=manager.ins_addr,
                               vex_block_addr=manager.block_addr,
                               vex_stmt_idx=manager.vex_stmt_idx,
                               )
        elif op_name is None:
            # is it a conversion?
            simop = vexop_to_simop(expr.op)
            if simop._conversion:
                if simop._from_side == "HI":
                    # returns the high-half of the argument
                    inner = VEXExprConverter.convert(expr.args[0], manager)
                    shifted = BinaryOp(manager.next_atom(),
                                       "Shr",
                                       [inner, Const(manager.next_atom(), None, simop._to_size, 8)],
                                       False
                                       )
                    return Convert(manager.next_atom(),
                               simop._from_size,
                               simop._to_size,
                               simop.is_signed,
                               shifted,
                               ins_addr=manager.ins_addr,
                               vex_block_addr=manager.block_addr,
                               vex_stmt_idx=manager.vex_stmt_idx,
                               )

                return Convert(manager.next_atom(),
                               simop._from_size,
                               simop._to_size,
                               simop.is_signed,
                               VEXExprConverter.convert(expr.args[0], manager),
                               ins_addr=manager.ins_addr,
                               vex_block_addr=manager.block_addr,
                               vex_stmt_idx=manager.vex_stmt_idx,
                               )
            raise NotImplementedError('Unsupported operation')

        return UnaryOp(manager.next_atom(),
                       op_name,
                       VEXExprConverter.convert(expr.args[0], manager),
                       ins_addr=manager.ins_addr,
                       vex_block_addr=manager.block_addr,
                       vex_stmt_idx=manager.vex_stmt_idx,
                       )

    @staticmethod
    def Binop(expr, manager):
        op = VEXExprConverter.simop_from_vexop(expr.op)
        op_name = op._generic_name
        operands = VEXExprConverter.convert_list(expr.args, manager)

        if op_name == 'Add' and \
                type(operands[1]) is Const and \
                operands[1].sign_bit == 1:
            # convert it to a sub
            op_name = 'Sub'
            op1_val, op1_bits = operands[1].value, operands[1].bits
            operands[1] = Const(operands[1].idx, None, (1 << op1_bits) - op1_val, op1_bits)

        signed = False
        if op_name in {'CmpLE', 'CmpLT', 'CmpGE', 'CmpGT', 'Div', 'DivMod', 'Mul', 'Mull'}:
            if vexop_to_simop(expr.op).is_signed:
                signed = True
        if op_name == "Cmp" and op._float:
            # Rename Cmp to CmpF
            op_name = "CmpF"

        if op_name is None and op._conversion:
            # conversion
            # TODO: Finish this
            if op._from_type == "I" and op._to_type == "F":
                # integer to floating point
                # TODO: Create an FPConvert operation
                op_name = "FPConvert"
                l.warning("Floating-point conversions are not supported in AIL or angr decompiler.")
            elif op._from_side == "HL":
                # Concatenating the two arguments and form a new value
                op_name = "Concat"

        bits = op._output_size_bits

        return BinaryOp(manager.next_atom(),
                        op_name,
                        operands,
                        signed,
                        ins_addr=manager.ins_addr,
                        vex_block_addr=manager.block_addr,
                        vex_stmt_idx=manager.vex_stmt_idx,
                        bits=bits,
                        )

    @staticmethod
    def Const(expr, manager):
        # pyvex.IRExpr.Const
        return Const(manager.next_atom(), None, expr.con.value, expr.result_size(manager.tyenv),
                     ins_addr=manager.ins_addr,
                     vex_block_addr=manager.block_addr,
                     vex_stmt_idx=manager.vex_stmt_idx,
                     )

    @staticmethod
    def const_n(expr, manager):
        # pyvex.const.xxx
        return Const(manager.next_atom(), None, expr.value, expr.size,
                     ins_addr=manager.ins_addr,
                     vex_block_addr=manager.block_addr,
                     vex_stmt_idx=manager.vex_stmt_idx,
                     )

    @staticmethod
    def ITE(expr, manager):
        cond = VEXExprConverter.convert(expr.cond, manager)
        iffalse = VEXExprConverter.convert(expr.iffalse, manager)
        iftrue = VEXExprConverter.convert(expr.iftrue, manager)

        return ITE(manager.next_atom(), cond, iffalse, iftrue,
                   ins_addr=manager.ins_addr,
                   vex_block_addr=manager.block_addr,
                   vex_stmt_idx=manager.vex_stmt_idx,
                   )


EXPRESSION_MAPPINGS = {
    pyvex.IRExpr.RdTmp: VEXExprConverter.RdTmp,
    pyvex.IRExpr.Get: VEXExprConverter.Get,
    pyvex.IRExpr.Unop: VEXExprConverter.Unop,
    pyvex.IRExpr.Binop: VEXExprConverter.Binop,
    pyvex.IRExpr.Const: VEXExprConverter.Const,
    pyvex.const.U32: VEXExprConverter.const_n,
    pyvex.const.U64: VEXExprConverter.const_n,
    pyvex.IRExpr.Load: VEXExprConverter.Load,
    pyvex.IRExpr.ITE: VEXExprConverter.ITE,
}


class VEXStmtConverter(Converter):

    @staticmethod
    def convert(idx, stmt, manager):  # pylint:disable=arguments-differ
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

        return Assignment(idx, var, reg, ins_addr=manager.ins_addr,
                          vex_block_addr=manager.block_addr,
                          vex_stmt_idx=manager.vex_stmt_idx)

    @staticmethod
    def Put(idx, stmt, manager):
        data = VEXExprConverter.convert(stmt.data, manager)
        reg = VEXExprConverter.register(stmt.offset, data.bits, manager)
        return Assignment(idx, reg, data, ins_addr=manager.ins_addr,
                          vex_block_addr=manager.block_addr,
                          vex_stmt_idx=manager.vex_stmt_idx)

    @staticmethod
    def Store(idx, stmt, manager):

        return Store(idx,
                     VEXExprConverter.convert(stmt.addr, manager),
                     VEXExprConverter.convert(stmt.data, manager),
                     stmt.data.result_size(manager.tyenv) // 8,
                     stmt.endness,
                     ins_addr=manager.ins_addr,
                     vex_block_addr=manager.block_addr,
                     vex_stmt_idx=manager.vex_stmt_idx,
                     )

    @staticmethod
    def Exit(idx, stmt, manager):

        if stmt.jumpkind in {'Ijk_EmWarn', 'Ijk_NoDecode',
                              'Ijk_MapFail', 'Ijk_NoRedir',
                              'Ijk_SigTRAP', 'Ijk_SigSEGV',
                              'Ijk_ClientReq', 'Ijk_SigFPE_IntDiv'}:
            raise SkipConversionNotice()

        return ConditionalJump(idx,
                               VEXExprConverter.convert(stmt.guard, manager),
                               VEXExprConverter.convert(stmt.dst, manager),
                               None,  # it will be filled in right afterwards
                               ins_addr=manager.ins_addr,
                               vex_block_addr=manager.block_addr,
                               vex_stmt_idx=manager.vex_stmt_idx,
                               )

    @staticmethod
    def LoadG(idx, stmt: pyvex.IRStmt.LoadG, manager):

        sizes = {
            'ILGop_Ident32': (32, 32, False),
            'ILGop_Ident64': (64, 64, False),
            'ILGop_IdentV128': (128, 128, False),
            'ILGop_8Uto32': (8, 32, False),
            'ILGop_8Sto32': (8, 32, True),
            'ILGop_16Uto32': (16, 32, False),
            'ILGop_16Sto32': (16, 32, True),
        }

        dst = VEXExprConverter.tmp(stmt.dst, manager.tyenv.sizeof(stmt.dst) // 8, manager)
        load_bits, convert_bits, signed = sizes[stmt.cvt]
        src = Load(manager.next_atom(),
                   VEXExprConverter.convert(stmt.addr, manager),
                   load_bits // 8,
                   stmt.end,
                   guard=VEXExprConverter.convert(stmt.guard, manager),
                   alt=VEXExprConverter.convert(stmt.alt, manager))
        if convert_bits != load_bits:
            src = Convert(manager.next_atom(), load_bits, convert_bits, signed, src)

        return Assignment(idx, dst, src, ins_addr=manager.ins_addr,
                          vex_block_addr=manager.block_addr,
                          vex_stmt_idx=manager.vex_stmt_idx)

    @staticmethod
    def StoreG(idx, stmt: pyvex.IRStmt.StoreG, manager):

        return Store(idx,
                     VEXExprConverter.convert(stmt.addr, manager),
                     VEXExprConverter.convert(stmt.data, manager),
                     stmt.data.result_size(manager.tyenv) // 8,
                     stmt.endness,
                     guard=VEXExprConverter.convert(stmt.guard, manager),
                     ins_addr=manager.ins_addr,
                     vex_block_addr=manager.block_addr,
                     vex_stmt_idx=manager.vex_stmt_idx,
                     )

    @staticmethod
    def CAS(idx, stmt: pyvex.IRStmt.CAS, manager):
        # compare-and-swap is translated into multiple statements. the atomic property is lost.

        stmts = []

        double = stmt.dataHi is not None
        ty = stmt.expdLo.result_type(manager.tyenv)
        if double:
            ty, narrow_to_bits, widen_from_bits, widen_to_bits = {
                'Ity_I8': ('Ity_I16', 8, 8, 16),
                'Ity_I16': ('Ity_I32', 16, 16, 32),
                'Ity_I32': ('Ity_I64', 32, 32, 64),
                'Ity_I64': ('Ity_V128', 64, 64, 128),
            }[ty]
            dataHi = VEXExprConverter.convert(stmt.dataHi, manager)
            dataLo = VEXExprConverter.convert(stmt.dataLo, manager)
            data = BinaryOp(idx, "Concat", (dataHi, dataLo), False)

            expdHi = Convert(idx, widen_from_bits, widen_to_bits, False, VEXExprConverter.convert(stmt.dataHi, manager))
            expdLo = Convert(idx, widen_from_bits, widen_to_bits, False, VEXExprConverter.convert(stmt.dataLo, manager))
            expd = BinaryOp(idx, "Concat", (expdHi, expdLo), False)
        else:
            narrow_to_bits = widen_to_bits = None
            data = VEXExprConverter.convert(stmt.dataLo, manager)
            expd = VEXExprConverter.convert(stmt.expdLo, manager)

        size = {
            'Ity_I8': 1,
            'Ity_I16': 2,
            'Ity_I32': 4,
            'Ity_I64': 8,
            'Ity_V128': 16,
        }[ty]

        # load value from memory
        addr = VEXExprConverter.convert(stmt.addr, manager)
        val = Load(
            idx,
            addr,
            size,
            stmt.endness,
        )
        cmp = BinaryOp(idx, 'CmpEQ', (val, expd), False)
        store = Store(
            idx,
            addr.copy(),
            data,
            size,
            stmt.endness,
            guard=cmp,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )
        stmts.append(store)

        if double:
            val_shifted = BinaryOp(idx, "Shr", (val, narrow_to_bits), False)
            valHi = Convert(idx, widen_to_bits, narrow_to_bits, False, val_shifted)
            valLo = Convert(idx, widen_to_bits, narrow_to_bits, False, val)

            wrtmp_0 = Assignment(idx, Tmp(idx, None, stmt.oldLo, narrow_to_bits), valLo,
                                 ins_addr=manager.ins_addr,
                                 vex_block_addr=manager.block_addr,
                                 vex_stmt_idx=manager.vex_stmt_idx,
                                 )
            wrtmp_1 = Assignment(idx, Tmp(idx, None, stmt.oldHi, narrow_to_bits), valHi,
                                 ins_addr=manager.ins_addr,
                                 vex_block_addr=manager.block_addr,
                                 vex_stmt_idx=manager.vex_stmt_idx,
                                 )
            stmts.append(wrtmp_0)
            stmts.append(wrtmp_1)
        else:
            wrtmp = Assignment(idx,  Tmp(idx, None, stmt.oldLo, size), val,
                               ins_addr=manager.ins_addr,
                               vex_block_addr=manager.block_addr,
                               vex_stmt_idx=manager.vex_stmt_idx,
                               )
            stmts.append(wrtmp)

        return stmts


STATEMENT_MAPPINGS = {
    pyvex.IRStmt.Put: VEXStmtConverter.Put,
    pyvex.IRStmt.WrTmp: VEXStmtConverter.WrTmp,
    pyvex.IRStmt.Store: VEXStmtConverter.Store,
    pyvex.IRStmt.Exit: VEXStmtConverter.Exit,
    pyvex.IRStmt.StoreG: VEXStmtConverter.StoreG,
    pyvex.IRStmt.LoadG: VEXStmtConverter.LoadG,
    pyvex.IRStmt.CAS: VEXStmtConverter.CAS,
}

class VEXIRSBConverter(Converter):

    @staticmethod
    def convert(irsb, manager):  # pylint:disable=arguments-differ
        """

        :param irsb:
        :param manager:
        :return:
        """

        # convert each VEX statement into an AIL statement
        statements = [ ]
        idx = 0

        manager.tyenv = irsb.tyenv
        manager.block_addr = irsb.addr

        addr = irsb.addr
        first_imark = True

        conditional_jumps = [ ]

        for vex_stmt_idx, stmt in enumerate(irsb.statements):
            if type(stmt) is pyvex.IRStmt.IMark:
                if first_imark:
                    # update block address
                    addr = stmt.addr + stmt.delta
                    first_imark = False
                manager.ins_addr = stmt.addr + stmt.delta
                continue
            if type(stmt) is pyvex.IRStmt.AbiHint:
                # TODO: How can we use AbiHint?
                continue

            manager.vex_stmt_idx = vex_stmt_idx
            try:
                converted = VEXStmtConverter.convert(idx, stmt, manager)
                if type(converted) is list:
                    # got multiple statements
                    statements.extend(converted)
                    idx += len(converted)
                else:
                    # got one statement
                    statements.append(converted)
                    if type(converted) is ConditionalJump:
                        conditional_jumps.append(converted)
                    idx += 1
            except SkipConversionNotice:
                pass

        manager.vex_stmt_idx = DEFAULT_STATEMENT
        if irsb.jumpkind == 'Ijk_Call':
            # call

            # TODO: is there a conditional call?

            ret_reg_offset = manager.arch.ret_offset
            ret_expr = Register(manager.next_atom(), None, ret_reg_offset, manager.arch.bits,
                                reg_name=manager.arch.translate_register_name(ret_reg_offset, size=manager.arch.bits))

            statements.append(Call(manager.next_atom(),
                                   VEXExprConverter.convert(irsb.next, manager),
                                   ret_expr=ret_expr,
                                   ins_addr=manager.ins_addr,
                                   vex_block_addr=manager.block_addr,
                                   vex_stmt_idx=DEFAULT_STATEMENT,
                                   )
                              )
        elif irsb.jumpkind == 'Ijk_Boring':
            if len(conditional_jumps) == 1:
                # fill in the false target
                cond_jump = conditional_jumps[0]
                cond_jump.false_target = VEXExprConverter.convert(irsb.next, manager)

            else:
                # jump
                statements.append(Jump(manager.next_atom(),
                                       VEXExprConverter.convert(irsb.next, manager),
                                       ins_addr=manager.ins_addr,
                                       vex_block_addr=manager.block_addr,
                                       vex_stmt_idx=DEFAULT_STATEMENT,
                                       )
                                  )
        elif irsb.jumpkind == 'Ijk_Ret':
            # return
            statements.append(Return(manager.next_atom(),
                                     VEXExprConverter.convert(irsb.next, manager),
                                     [ ],
                                     ins_addr=manager.ins_addr,
                                     vex_block_addr=manager.block_addr,
                                     vex_stmt_idx=DEFAULT_STATEMENT,
                                     )
                              )

        return Block(addr, irsb.size, statements=statements)

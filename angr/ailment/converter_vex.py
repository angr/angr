# pylint:disable=missing-class-docstring
from __future__ import annotations
import logging

import pyvex
from angr.utils.constants import DEFAULT_STATEMENT
from angr.engines.vex.claripy.irop import vexop_to_simop
from angr.errors import UnsupportedIROpError

from .block import Block
from .statement import Assignment, CAS, Store, Jump, Call, ConditionalJump, DirtyStatement, Return
from .expression import (
    Const,
    Register,
    Tmp,
    DirtyExpression,
    UnaryOp,
    Convert,
    BinaryOp,
    Load,
    ITE,
    Reinterpret,
    VEXCCallExpression,
)
from .converter_common import SkipConversionNotice, Converter


log = logging.getLogger(name=__name__)


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
        if isinstance(expr, pyvex.const.IRConst):
            return VEXExprConverter.const_n(expr, manager)

        func = EXPRESSION_MAPPINGS.get(type(expr))
        if func is not None:
            # When something goes wrong, return a DirtyExpression instead of crashing the program
            try:
                return func(expr, manager)
            except UnsupportedIROpError:
                log.warning("VEXExprConverter: Unsupported IROp %s.", expr.op)
                return DirtyExpression(
                    manager.next_atom(), f"unsupported_{expr.op}", [], bits=expr.result_size(manager.tyenv)
                )

        log.warning("VEXExprConverter: Unsupported VEX expression of type %s.", type(expr))
        try:
            bits = expr.result_size(manager.tyenv)
        except ValueError:
            # e.g., "ValueError: Type Ity_INVALID does not have size"
            bits = 0
        return DirtyExpression(manager.next_atom(), f"unsupported_{type(expr)!s}", [], bits=bits)

    @staticmethod
    def convert_list(exprs, manager):
        converted = []
        for expr in exprs:
            converted.append(VEXExprConverter.convert(expr, manager))
        return converted

    @staticmethod
    def register(offset, bits, manager):
        reg_size = bits // manager.arch.byte_width
        reg_name = manager.arch.translate_register_name(offset, reg_size)
        return Register(
            manager.next_atom(),
            None,
            offset,
            bits,
            reg_name=reg_name,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )

    @staticmethod
    def tmp(tmp_idx, bits, manager):
        return Tmp(
            manager.next_atom(),
            None,
            tmp_idx,
            bits,
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
        return Load(
            manager.next_atom(),
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
            return Reinterpret(
                manager.next_atom(),
                simop._from_size,
                simop._from_type,
                simop._to_size,
                simop._to_type,
                VEXExprConverter.convert(expr.args[0], manager),
                ins_addr=manager.ins_addr,
                vex_block_addr=manager.block_addr,
                vex_stmt_idx=manager.vex_stmt_idx,
            )
        if op_name is None:
            # is it a conversion?
            simop = vexop_to_simop(expr.op)
            if simop._conversion:
                if simop._from_side == "HI":
                    # returns the high-half of the argument
                    inner = VEXExprConverter.convert(expr.args[0], manager)
                    shifted = BinaryOp(
                        manager.next_atom(),
                        "Shr",
                        [
                            inner,
                            Const(
                                manager.next_atom(),
                                None,
                                simop._to_size,
                                8,
                                ins_addr=manager.ins_addr,
                                vex_block_addr=manager.block_addr,
                                vex_stmt_idx=manager.vex_stmt_idx,
                            ),
                        ],
                        False,
                        ins_addr=manager.ins_addr,
                        vex_block_addr=manager.block_addr,
                        vex_stmt_idx=manager.vex_stmt_idx,
                    )
                    return Convert(
                        manager.next_atom(),
                        simop._from_size,
                        simop._to_size,
                        simop.is_signed,
                        shifted,
                        ins_addr=manager.ins_addr,
                        vex_block_addr=manager.block_addr,
                        vex_stmt_idx=manager.vex_stmt_idx,
                    )

                return Convert(
                    manager.next_atom(),
                    simop._from_size,
                    simop._to_size,
                    simop.is_signed,
                    VEXExprConverter.convert(expr.args[0], manager),
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=manager.vex_stmt_idx,
                )
            raise NotImplementedError("Unsupported operation")
        if op_name == "Not" and expr.op != "Iop_Not1":
            # NotN (N != 1) is equivalent to bitwise negation
            op_name = "BitwiseNeg"

        return UnaryOp(
            manager.next_atom(),
            op_name,
            VEXExprConverter.convert(expr.args[0], manager),
            bits=expr.result_size(manager.tyenv),
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )

    @staticmethod
    def Binop(expr, manager):
        op = VEXExprConverter.simop_from_vexop(expr.op)
        op_name = op._generic_name
        operands = VEXExprConverter.convert_list(expr.args, manager)

        if op_name == "Add" and type(operands[1]) is Const and operands[1].sign_bit == 1:
            # convert it to a sub
            op_name = "Sub"
            op1_val, op1_bits = operands[1].value, operands[1].bits
            operands[1] = Const(operands[1].idx, None, (1 << op1_bits) - op1_val, op1_bits)

        signed = False
        vector_count = None
        vector_size = None
        if op._vector_count is not None and op._vector_size is not None:
            # SIMD conversions
            op_name += "V"  # vectorized
            vector_count = op._vector_count
            vector_size = op._vector_size
        elif op_name in {"CmpLE", "CmpLT", "CmpGE", "CmpGT", "Div", "DivMod", "Mod", "Mul", "Mull"}:
            if op.is_signed:
                signed = True

        if op_name == "Cmp" and op._float:
            # Rename Cmp to CmpF
            op_name = "CmpF"

        if op_name is None and op._conversion:
            # conversion
            # TODO: Finish this
            if op._from_type == "I" and op._to_type == "F":
                # integer to floating point
                rm = operands[0]
                operand = operands[1]
                return Convert(
                    manager.next_atom(),
                    op._from_size,
                    op._to_size,
                    op.is_signed,
                    operand,
                    from_type=Convert.TYPE_INT,
                    to_type=Convert.TYPE_FP,
                    rounding_mode=rm,
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=manager.vex_stmt_idx,
                )
            if op._from_side == "HL":
                # Concatenating the two arguments and form a new value
                op_name = "Concat"
            elif op._from_type == "F" and op._to_type == "F":
                # floating point to floating point
                rm = operands[0]
                operand = operands[1]
                return Convert(
                    manager.next_atom(),
                    op._from_size,
                    op._to_size,
                    op.is_signed,
                    operand,
                    from_type=Convert.TYPE_FP,
                    to_type=Convert.TYPE_FP,
                    rounding_mode=rm,
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=manager.vex_stmt_idx,
                )
            elif op._from_type == "F" and op._to_type == "I":
                # floating point to integer
                # floating point to floating point
                rm = operands[0]
                operand = operands[1]
                return Convert(
                    manager.next_atom(),
                    op._from_size,
                    op._to_size,
                    op.is_signed,
                    operand,
                    from_type=Convert.TYPE_FP,
                    to_type=Convert.TYPE_INT,
                    rounding_mode=rm,
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=manager.vex_stmt_idx,
                )

        bits = op._output_size_bits

        if op_name == "DivMod":
            op1_size = op._from_size if op._from_size is not None else operands[0].bits
            op2_size = op._to_size if op._to_size is not None else operands[1].bits

            if op2_size < op1_size:
                # e.g., DivModU64to32
                operands[1] = Convert(
                    manager.next_atom(),
                    op2_size,
                    op1_size,
                    op._from_signed != "U",
                    operands[1],
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=manager.vex_stmt_idx,
                )
            chunk_bits = bits // 2

            div = BinaryOp(
                manager.next_atom(),
                "Div",
                operands,
                signed,
                ins_addr=manager.ins_addr,
                vex_block_addr=manager.block_addr,
                vex_stmt_idx=manager.vex_stmt_idx,
                bits=op1_size,
            )
            truncated_div = Convert(
                manager.next_atom(),
                op1_size,
                chunk_bits,
                signed,
                div,
                ins_addr=manager.ins_addr,
                vex_block_addr=manager.block_addr,
                vex_stmt_idx=manager.vex_stmt_idx,
            )
            mod = BinaryOp(
                manager.next_atom(),
                "Mod",
                operands,
                signed,
                ins_addr=manager.ins_addr,
                vex_block_addr=manager.block_addr,
                vex_stmt_idx=manager.vex_stmt_idx,
                bits=op1_size,
            )
            truncated_mod = Convert(
                manager.next_atom(),
                op1_size,
                chunk_bits,
                signed,
                mod,
                ins_addr=manager.ins_addr,
                vex_block_addr=manager.block_addr,
                vex_stmt_idx=manager.vex_stmt_idx,
            )

            operands = [truncated_mod, truncated_div]
            op_name = "Concat"
            signed = False

        return BinaryOp(
            manager.next_atom(),
            op_name,
            operands,
            signed,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
            bits=bits,
            vector_count=vector_count,
            vector_size=vector_size,
        )

    @staticmethod
    def Triop(expr, manager):
        op = VEXExprConverter.simop_from_vexop(expr.op)
        op_name = op._generic_name
        operands = VEXExprConverter.convert_list(expr.args, manager)

        bits = op._output_size_bits

        if op._float:
            # this is a floating-point operation where the first argument is the rounding mode. in fact, we have a
            # BinaryOp here.
            rm = operands[0]
            return BinaryOp(
                manager.next_atom(),
                op_name,
                operands[1:],
                True,  # all floating-point operations are signed
                floating_point=True,
                rounding_mode=rm,
                ins_addr=manager.ins_addr,
                vex_block_addr=manager.block_addr,
                vex_stmt_idx=manager.vex_stmt_idx,
                bits=bits,
            )

        raise TypeError(
            "Please figure out what kind of operation this is (smart money says fused multiply) and convert it into "
            "multiple binops"
        )

    @staticmethod
    def Const(expr, manager):
        # pyvex.IRExpr.Const
        return Const(
            manager.next_atom(),
            None,
            expr.con.value,
            expr.result_size(manager.tyenv),
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )

    @staticmethod
    def const_n(expr, manager):
        # pyvex.const.xxx
        return Const(
            manager.next_atom(),
            None,
            expr.value,
            expr.size,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )

    @staticmethod
    def ITE(expr, manager):
        cond = VEXExprConverter.convert(expr.cond, manager)
        iffalse = VEXExprConverter.convert(expr.iffalse, manager)
        iftrue = VEXExprConverter.convert(expr.iftrue, manager)

        return ITE(
            manager.next_atom(),
            cond,
            iffalse,
            iftrue,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )

    @staticmethod
    def CCall(expr: pyvex.IRExpr.CCall, manager):
        operands = [VEXExprConverter.convert(arg, manager) for arg in expr.args]
        return VEXCCallExpression(
            manager.next_atom(),
            expr.cee.name,
            operands,
            bits=expr.result_size(manager.tyenv),
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )


EXPRESSION_MAPPINGS = {
    pyvex.IRExpr.RdTmp: VEXExprConverter.RdTmp,
    pyvex.IRExpr.Get: VEXExprConverter.Get,
    pyvex.IRExpr.Unop: VEXExprConverter.Unop,
    pyvex.IRExpr.Binop: VEXExprConverter.Binop,
    pyvex.IRExpr.Triop: VEXExprConverter.Triop,
    pyvex.IRExpr.Const: VEXExprConverter.Const,
    pyvex.const.U32: VEXExprConverter.const_n,
    pyvex.const.U64: VEXExprConverter.const_n,
    pyvex.IRExpr.Load: VEXExprConverter.Load,
    pyvex.IRExpr.ITE: VEXExprConverter.ITE,
    pyvex.IRExpr.CCall: VEXExprConverter.CCall,
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
            dirty = DirtyExpression(manager.next_atom(), str(stmt), [], bits=0)
            return DirtyStatement(idx, dirty, ins_addr=manager.ins_addr)

        return func(idx, stmt, manager)

    @staticmethod
    def WrTmp(idx, stmt, manager):
        var = VEXExprConverter.tmp(stmt.tmp, stmt.data.result_size(manager.tyenv), manager)
        reg = VEXExprConverter.convert(stmt.data, manager)

        return Assignment(
            idx,
            var,
            reg,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )

    @staticmethod
    def Put(idx, stmt, manager):
        data = VEXExprConverter.convert(stmt.data, manager)
        reg = VEXExprConverter.register(stmt.offset, data.bits, manager)
        return Assignment(
            idx,
            reg,
            data,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )

    @staticmethod
    def Store(idx, stmt, manager):
        return Store(
            idx,
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
        if stmt.jumpkind in {
            "Ijk_EmWarn",
            "Ijk_NoDecode",
            "Ijk_MapFail",
            "Ijk_NoRedir",
            "Ijk_SigTRAP",
            "Ijk_SigSEGV",
            "Ijk_ClientReq",
            "Ijk_SigFPE_IntDiv",
        }:
            raise SkipConversionNotice

        return ConditionalJump(
            idx,
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
            "ILGop_Ident32": (32, 32, False),
            "ILGop_Ident64": (64, 64, False),
            "ILGop_IdentV128": (128, 128, False),
            "ILGop_8Uto32": (8, 32, False),
            "ILGop_8Sto32": (8, 32, True),
            "ILGop_16Uto32": (16, 32, False),
            "ILGop_16Sto32": (16, 32, True),
        }

        dst = VEXExprConverter.tmp(stmt.dst, manager.tyenv.sizeof(stmt.dst), manager)
        load_bits, convert_bits, signed = sizes[stmt.cvt]
        src = Load(
            manager.next_atom(),
            VEXExprConverter.convert(stmt.addr, manager),
            load_bits // 8,
            stmt.end,
            guard=VEXExprConverter.convert(stmt.guard, manager),
            alt=VEXExprConverter.convert(stmt.alt, manager),
        )
        if convert_bits != load_bits:
            src = Convert(manager.next_atom(), load_bits, convert_bits, signed, src)

        return Assignment(
            idx,
            dst,
            src,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )

    @staticmethod
    def StoreG(idx, stmt: pyvex.IRStmt.StoreG, manager):
        return Store(
            idx,
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
        # addr
        addr = VEXExprConverter.convert(stmt.addr, manager)
        data_lo = VEXExprConverter.convert(stmt.dataLo, manager)
        data_hi = VEXExprConverter.convert(stmt.dataHi, manager) if stmt.dataHi is not None else None
        expd_lo = VEXExprConverter.convert(stmt.expdLo, manager)
        expd_hi = VEXExprConverter.convert(stmt.expdHi, manager) if stmt.expdHi is not None else None
        old_lo = VEXExprConverter.tmp(stmt.oldLo, manager.tyenv.sizeof(stmt.oldLo), manager)
        old_hi = (
            VEXExprConverter.tmp(stmt.oldHi, stmt.oldHi.result_size(manager.tyenv), manager)
            if stmt.oldHi != 0xFFFFFFFF
            else None
        )
        return CAS(
            idx, addr, data_lo, data_hi, expd_lo, expd_hi, old_lo, old_hi, stmt.endness, ins_addr=manager.ins_addr
        )

    @staticmethod
    def Dirty(idx, stmt: pyvex.IRStmt.Dirty, manager):
        # we translate it into tmp = DirtyExpression() if possible

        operands = [VEXExprConverter.convert(op, manager) for op in stmt.args]
        guard = VEXExprConverter.convert(stmt.guard, manager) if stmt.guard is not None else None
        bits = manager.tyenv.sizeof(stmt.tmp) if stmt.tmp != 0xFFFFFFFF else 0
        maddr = VEXExprConverter.convert(stmt.mAddr, manager) if stmt.mAddr is not None else None
        dirty_expr = DirtyExpression(
            manager.next_atom(),
            stmt.cee.name,
            operands,
            guard=guard,
            mfx=stmt.mFx,
            maddr=maddr,
            msize=stmt.mSize,
            bits=bits,
        )

        if stmt.tmp == 0xFFFFFFFF:
            return DirtyStatement(
                idx,
                dirty_expr,
                ins_addr=manager.ins_addr,
                vex_block_addr=manager.block_addr,
                vex_stmt_idx=manager.vex_stmt_idx,
            )

        tmp = VEXExprConverter.tmp(stmt.tmp, bits, manager)
        return Assignment(
            idx,
            tmp,
            dirty_expr,
            ins_addr=manager.ins_addr,
            vex_block_addr=manager.block_addr,
            vex_stmt_idx=manager.vex_stmt_idx,
        )


STATEMENT_MAPPINGS = {
    pyvex.IRStmt.Put: VEXStmtConverter.Put,
    pyvex.IRStmt.WrTmp: VEXStmtConverter.WrTmp,
    pyvex.IRStmt.Store: VEXStmtConverter.Store,
    pyvex.IRStmt.Exit: VEXStmtConverter.Exit,
    pyvex.IRStmt.StoreG: VEXStmtConverter.StoreG,
    pyvex.IRStmt.LoadG: VEXStmtConverter.LoadG,
    pyvex.IRStmt.CAS: VEXStmtConverter.CAS,
    pyvex.IRStmt.Dirty: VEXStmtConverter.Dirty,
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
        statements = []
        idx = 0

        manager.tyenv = irsb.tyenv
        manager.block_addr = irsb.addr

        addr = irsb.addr
        first_imark = True

        conditional_jumps = []

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
                if isinstance(converted, list):
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
        if irsb.jumpkind == "Ijk_Call" or irsb.jumpkind.startswith("Ijk_Sys"):
            # FIXME: Move ret_expr and fp_ret_expr creation into angr because we cannot reliably determine which
            #  expressions can be returned from the call without performing further analysis
            ret_reg_offset = manager.arch.ret_offset
            ret_expr = Register(
                manager.next_atom(),
                None,
                ret_reg_offset,
                manager.arch.bits,
                reg_name=manager.arch.translate_register_name(ret_reg_offset, size=manager.arch.bits),
                ins_addr=manager.ins_addr,
                vex_block_addr=manager.block_addr,
                vex_stmt_idx=DEFAULT_STATEMENT,
            )
            fp_ret_reg_offset = manager.arch.fp_ret_offset
            if fp_ret_reg_offset is not None and fp_ret_reg_offset != ret_reg_offset:
                fp_ret_expr = Register(
                    manager.next_atom(),
                    None,
                    fp_ret_reg_offset,
                    manager.arch.bits,
                    reg_name=manager.arch.translate_register_name(fp_ret_reg_offset, size=manager.arch.bits),
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=DEFAULT_STATEMENT,
                )
            else:
                fp_ret_expr = None

            if irsb.jumpkind == "Ijk_Call":
                target = VEXExprConverter.convert(irsb.next, manager)
            elif irsb.jumpkind.startswith("Ijk_Sys"):
                # FIXME: This is a hack to make syscall work. We should have a better way to handle syscalls.
                target = DirtyExpression(manager.next_atom(), "syscall", [], bits=manager.arch.bits)
            else:
                raise NotImplementedError("Unsupported jumpkind")

            statements.append(
                Call(
                    manager.next_atom(),
                    target,
                    ret_expr=ret_expr,
                    fp_ret_expr=fp_ret_expr,
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=DEFAULT_STATEMENT,
                )
            )
        elif irsb.jumpkind == "Ijk_Boring":
            if conditional_jumps:
                # fill in the false target
                cond_jump = conditional_jumps[-1]
                cond_jump.false_target = VEXExprConverter.convert(irsb.next, manager)

            else:
                # jump
                statements.append(
                    Jump(
                        manager.next_atom(),
                        VEXExprConverter.convert(irsb.next, manager),
                        ins_addr=manager.ins_addr,
                        vex_block_addr=manager.block_addr,
                        vex_stmt_idx=DEFAULT_STATEMENT,
                    )
                )
        elif irsb.jumpkind == "Ijk_Ret":
            # return
            statements.append(
                Return(
                    manager.next_atom(),
                    [],
                    ins_addr=manager.ins_addr,
                    vex_block_addr=manager.block_addr,
                    vex_stmt_idx=DEFAULT_STATEMENT,
                )
            )
        else:
            raise NotImplementedError("Unsupported jumpkind")

        return Block(addr, irsb.size, statements=statements)

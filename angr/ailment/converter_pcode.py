from typing import Dict, Tuple, Optional
import logging

from angr.utils.constants import DEFAULT_STATEMENT
from angr.engines.pcode.lifter import IRSB
from pypcode import OpCode, Varnode
import pypcode

from .block import Block
from .statement import Statement, Assignment, Store, Jump, ConditionalJump, Return, Call
from .expression import Expression, DirtyExpression, Const, Register, Tmp, UnaryOp, BinaryOp, Load, Convert

# FIXME: Convert, ITE
from .manager import Manager
from .converter_common import Converter


log = logging.getLogger(name=__name__)

# FIXME: Not all ops are mapped to AIL expressions!
opcode_to_generic_name = {
    # OpCode.MULTIEQUAL        : '',
    # OpCode.INDIRECT          : '',
    # OpCode.PIECE             : '',
    # OpCode.SUBPIECE          : '',
    OpCode.INT_EQUAL: "CmpEQ",
    OpCode.INT_NOTEQUAL: "CmpNE",
    OpCode.INT_SLESS: "CmpLTs",
    OpCode.INT_SLESSEQUAL: "CmpLEs",
    OpCode.INT_LESS: "CmpLT",
    OpCode.INT_LESSEQUAL: "CmpLE",
    # OpCode.INT_ZEXT          : '',
    # OpCode.INT_SEXT          : '',
    OpCode.INT_ADD: "Add",
    OpCode.INT_SUB: "Sub",
    OpCode.INT_CARRY: "Carry",
    OpCode.INT_SCARRY: "SCarry",
    OpCode.INT_SBORROW: "SBorrow",
    # OpCode.INT_2COMP         : '',
    OpCode.INT_NEGATE: "Neg",
    OpCode.INT_XOR: "Xor",
    OpCode.INT_AND: "And",
    OpCode.INT_OR: "Or",
    OpCode.INT_LEFT: "Shl",
    OpCode.INT_RIGHT: "Shr",
    OpCode.INT_SRIGHT: "Sar",
    OpCode.INT_MULT: "Mul",
    OpCode.INT_DIV: "Div",
    # OpCode.INT_SDIV          : '',
    # OpCode.INT_REM           : '',
    # OpCode.INT_SREM          : '',
    OpCode.BOOL_NEGATE: "Not",
    OpCode.BOOL_XOR: "LogicalXor",
    OpCode.BOOL_AND: "LogicalAnd",
    OpCode.BOOL_OR: "LogicalOr",
    # OpCode.CAST              : '',
    # OpCode.PTRADD            : '',
    # OpCode.PTRSUB            : '',
    # OpCode.FLOAT_EQUAL       : '',
    # OpCode.FLOAT_NOTEQUAL    : '',
    # OpCode.FLOAT_LESS        : '',
    # OpCode.FLOAT_LESSEQUAL   : '',
    # OpCode.FLOAT_NAN         : '',
    # OpCode.FLOAT_ADD         : '',
    OpCode.FLOAT_DIV: "Div",
    OpCode.FLOAT_MULT: "Mul",
    OpCode.FLOAT_SUB: "Sub",
    # OpCode.FLOAT_NEG         : '',
    # OpCode.FLOAT_ABS         : '',
    # OpCode.FLOAT_SQRT        : '',
    # OpCode.FLOAT_INT2FLOAT   : '',
    # OpCode.FLOAT_FLOAT2FLOAT : '',
    # OpCode.FLOAT_TRUNC       : '',
    # OpCode.FLOAT_CEIL        : '',
    # OpCode.FLOAT_FLOOR       : '',
    # OpCode.FLOAT_ROUND       : '',
    # OpCode.SEGMENTOP         : '',
    # OpCode.CPOOLREF          : '',
    # OpCode.NEW               : '',
    # OpCode.INSERT            : '',
    # OpCode.EXTRACT           : '',
    # OpCode.POPCOUNT          : '',
}


class PCodeIRSBConverter(Converter):
    """
    Converts a p-code IRSB to an AIL block
    """

    @staticmethod
    def convert(irsb: IRSB, manager: Manager):  # pylint:disable=arguments-differ
        """
        Convert the given IRSB to an AIL block

        :param irsb:    IRSB to convert
        :param manager: Manager to use
        :return:        Converted block
        """
        return PCodeIRSBConverter(irsb, manager)._convert()

    def __init__(self, irsb: IRSB, manager: Manager):
        self._irsb = irsb
        self._manager = manager
        self._statements = []
        self._current_op = None
        self._next_ins_addr = None
        self._current_behavior = None
        self._statement_idx = 0

        # Remap all uniques s.t. they are write-once with values starting from 0
        self._unique_tracker: Dict[int, Tuple[int, int]] = {}
        self._unique_counter = 0

        self._special_op_handlers = {
            OpCode.COPY: self._convert_copy,
            OpCode.INT_ZEXT: self._convert_zext,
            OpCode.INT_SEXT: self._convert_sext,
            OpCode.LOAD: self._convert_load,
            OpCode.STORE: self._convert_store,
            OpCode.BRANCH: self._convert_branch,
            OpCode.CBRANCH: self._convert_cbranch,
            OpCode.BRANCHIND: self._convert_branchind,
            OpCode.CALL: self._convert_call,
            OpCode.CALLIND: self._convert_callind,
            OpCode.CALLOTHER: self._convert_callother,
            OpCode.RETURN: self._convert_ret,
            OpCode.MULTIEQUAL: self._convert_multiequal,
            OpCode.INDIRECT: self._convert_indirect,
            OpCode.SEGMENTOP: self._convert_segment_op,
            OpCode.CPOOLREF: self._convert_cpool_ref,
            OpCode.NEW: self._convert_new,
            OpCode.FLOAT_INT2FLOAT: self._convert_int2float,
            OpCode.FLOAT_FLOAT2FLOAT: self._convert_float2float,
        }

        manager.tyenv = None
        manager.block_addr = irsb.addr
        manager.vex_stmt_idx = DEFAULT_STATEMENT  # Reset after loop. Necessary?

    def _convert(self) -> Block:
        """
        Convert the given IRSB to an AIL Block
        """
        self._statement_idx = 0

        for op in self._irsb._ops:
            self._current_op = op
            if op.opcode == pypcode.OpCode.IMARK:
                self._manager.ins_addr = op.inputs[0].offset
                self._next_ins_addr = op.inputs[-1].offset + op.inputs[-1].size
            else:
                self._current_behavior = self._irsb.behaviors.get_behavior_for_opcode(self._current_op.opcode)
                self._convert_current_op()
            self._statement_idx += 1

            if "sparc:" in self._irsb.arch.name and self._irsb.arch.bits == 32:
                if self._current_op.opcode == OpCode.CALL:
                    break

        return Block(self._irsb.addr, self._irsb.size, statements=self._statements)

    def _convert_current_op(self) -> None:
        """
        Convert the current op to corresponding AIL statement
        """
        assert self._current_behavior is not None

        is_special = self._current_behavior.opcode in self._special_op_handlers

        if is_special:
            try:
                self._special_op_handlers[self._current_behavior.opcode]()
            except NotImplementedError as ex:
                log.warning("Unsupported opcode: %s", ex)
        elif self._current_behavior.is_unary:
            self._convert_unary()
        else:
            self._convert_binary()

    def _convert_unary(self) -> None:
        """
        Convert the current unary op to corresponding AIL statement
        """
        opcode = self._current_op.opcode

        op = opcode_to_generic_name.get(opcode, None)
        in1 = self._get_value(self._current_op.inputs[0])
        if op is None:
            log.warning("p-code: Unsupported opcode of type %s", opcode.__name__)
            out = DirtyExpression(self._manager.next_atom(), opcode.__name__, bits=self._current_op.output.size * 8)
        else:
            out = UnaryOp(self._manager.next_atom(), op, in1, ins_addr=self._manager.ins_addr)

        stmt = self._set_value(self._current_op.output, out)
        self._statements.append(stmt)

    def _convert_binary(self) -> None:
        """
        Convert the current binary op to corresponding AIL statement
        """
        opcode = self._current_op.opcode
        op = opcode_to_generic_name.get(opcode, None)
        in1 = self._get_value(self._current_op.inputs[0])
        in2 = self._get_value(self._current_op.inputs[1])
        signed = op in {"CmpLEs", "CmpGTs"}

        if op is None:
            log.warning("p-code: Unsupported opcode of type %s.", opcode.__name__)
            out = DirtyExpression(self._manager.next_atom(), opcode.__name__, bits=self._current_op.output.size * 8)
        else:
            out = BinaryOp(self._manager.next_atom(), op, [in1, in2], signed, ins_addr=self._manager.ins_addr)

        # Zero-extend 1-bit results
        zextend_ops = {
            OpCode.INT_EQUAL,
            OpCode.INT_NOTEQUAL,
            OpCode.INT_SLESS,
            OpCode.INT_SLESSEQUAL,
            OpCode.INT_LESS,
            OpCode.INT_LESSEQUAL,
        }
        if opcode in zextend_ops:
            out = Convert(self._manager.next_atom(), 1, self._current_op.output.size * 8, False, out)

        stmt = self._set_value(self._current_op.output, out)
        self._statements.append(stmt)

    def _map_register_name(self, varnode: Varnode) -> int:
        """
        Map SLEIGH register offset to ArchInfo register offset based on name.

        :param varnode: The varnode to translate
        :return:        The register file offset
        """
        # FIXME: Will need performance optimization
        # FIXME: Should not get trans object this way. Moreover, should have a
        #        faster mapping method than going through trans
        reg_name = varnode.getRegisterName()
        try:
            reg_offset = self._manager.arch.get_register_offset(reg_name.lower())
            log.debug("Mapped register '%s' to offset %x", reg_name, reg_offset)
        except ValueError:
            reg_offset = varnode.offset + 0x100000
            log.warning("Could not map register '%s' from archinfo. Mapping to %x", reg_name, reg_offset)
        return reg_offset

    def _remap_temp(self, offset: int, size: int, is_write: bool) -> Optional[int]:
        """
        Remap any unique space addresses such that they are written only once

        :param offset:   The unique space address
        :param is_write: Whether the access is a write or a read
        :return:         The remapped temporary register index
        """
        if is_write:
            self._unique_tracker[offset] = self._unique_counter, size
            self._unique_counter += 1
            return self._unique_tracker[offset][0]
        else:
            if offset in self._unique_tracker:
                return self._unique_tracker[offset][0]
            # this might be a partial access of an existing temporary variable. return None for now
            return None

    def _convert_varnode(self, varnode: Varnode, is_write: bool) -> Expression:
        """
        Convert a varnode to a corresponding AIL expression

        :param varnode:  The varnode to remap
        :param is_write: Whether the varnode is being read or written to
        :return:         The corresponding AIL expression
        """
        space_name = varnode.space.name
        size = varnode.size * 8

        if space_name == "const":
            return Const(self._manager.next_atom(), None, varnode.offset, size)
        elif space_name == "register":
            offset = self._map_register_name(varnode)
            return Register(self._manager.next_atom(), None, offset, size, reg_name=varnode.getRegisterName())
        elif space_name == "unique":
            offset = self._remap_temp(varnode.offset, varnode.size, is_write)
            if offset is None:
                # this might be a partial access of an existing temporary variable
                unique_offset = None
                for delta in range(-1, -8, -1):
                    if varnode.offset + delta in self._unique_tracker:
                        unique_offset = varnode.offset + delta
                        break
                assert unique_offset is not None, "Cannot find the source unique variable"
                # TODO: Check size
                _, ori_tmp_size = self._unique_tracker[unique_offset]
                t = Tmp(self._manager.next_atom(), None, unique_offset, ori_tmp_size * 8)
                # FIXME: Asserting BE
                right_shift_amount = varnode.offset + varnode.size - (unique_offset + ori_tmp_size)
                if right_shift_amount != 0:
                    t = BinaryOp(
                        self._manager.next_atom(),
                        "Shr",
                        [t, Const(self._manager.next_atom(), None, right_shift_amount * 8, 8)],
                        False,
                        ins_addr=self._manager.ins_addr,
                    )
                return Convert(self._manager.next_atom(), t.bits, size, False, t, ins_addr=self._manager.ins_addr)

            return Tmp(self._manager.next_atom(), None, offset, size)
        elif space_name in ["ram", "mem"]:
            assert not is_write
            addr = Const(self._manager.next_atom(), None, varnode.offset, self._manager.arch.bits)
            # Note: Load takes bytes, not bits, for size
            return Load(
                self._manager.next_atom(),
                addr,
                varnode.size,
                self._manager.arch.memory_endness,
                ins_addr=self._manager.ins_addr,
            )
        else:
            raise NotImplementedError()

    def _set_value(self, varnode: Varnode, value: Expression) -> Statement:
        """
        Create the appropriate assignment statement to store to a varnode

        This method stores to the appropriate register, or unique space,
        depending on the space indicated by the varnode.

        :param varnode: Varnode to store into
        :param value:   Value to store
        :return:        Corresponding AIL statement
        """
        space_name = varnode.space.name

        if space_name in ["register", "unique"]:
            return Assignment(
                self._statement_idx, self._convert_varnode(varnode, True), value, ins_addr=self._manager.ins_addr
            )
        elif space_name in ["ram", "mem"]:
            addr = Const(self._manager.next_atom(), None, varnode.offset, self._manager.arch.bits)
            return Store(
                self._statement_idx,
                addr,
                value,
                varnode.size,
                self._manager.arch.memory_endness,
                ins_addr=self._manager.ins_addr,
            )
        else:
            raise NotImplementedError()

    def _get_value(self, varnode: Varnode) -> Expression:
        """
        Create the appropriate expression to load from a varnode

        This method loads from the appropriate const, register, unique, or RAM
        space, depending on the space indicated by the varnode.

        :param varnode: Varnode to load from.
        :return:        Value loaded
        """
        return self._convert_varnode(varnode, False)

    def _convert_copy(self) -> None:
        """
        Convert copy operation
        """
        out = self._current_op.output
        inp = self._get_value(self._current_op.inputs[0])
        stmt = self._set_value(out, inp)
        self._statements.append(stmt)

    def _convert_zext(self) -> None:
        """
        Convert zext operation
        """
        out = self._current_op.output
        inp = Convert(
            self._manager.next_atom(),
            self._current_op.inputs[0].size * 8,
            out.size * 8,
            False,
            self._get_value(self._current_op.inputs[0]),
        )
        stmt = self._set_value(out, inp)
        self._statements.append(stmt)

    def _convert_sext(self) -> None:
        """
        Convert the signed extension operation
        """
        out = self._current_op.output
        inp = Convert(
            self._manager.next_atom(),
            self._current_op.inputs[0].size * 8,
            out.size * 8,
            False,
            self._get_value(self._current_op.inputs[0]),
        )
        stmt = self._set_value(out, inp)
        self._statements.append(stmt)

    def _convert_negate(self) -> None:
        """
        Convert bool negate operation
        """
        out = self._current_op.output
        inp = self._get_value(self._current_op.inputs[0])

        cval = Const(self._manager.next_atom(), None, 0, self._current_op.inputs[0].size * 8)

        expr = BinaryOp(self._manager.next_atom(), "CmpEQ", [inp, cval], signed=False, ins_addr=self._manager.ins_addr)

        stmt = self._set_value(out, expr)
        self._statements.append(stmt)

    def _convert_load(self) -> None:
        """
        Convert a p-code load operation
        """
        spc = self._current_op.inputs[0].getSpaceFromConst()
        out = self._current_op.output
        assert spc.name in {"ram", "mem", "register"}
        if spc.name == "register":
            # load from register
            res = self._get_value(self._current_op.inputs[1])
            stmt = self._set_value(out, res)
        else:
            # load from memory
            off = self._get_value(self._current_op.inputs[1])
            res = Load(
                self._manager.next_atom(),
                off,
                self._current_op.output.size,
                self._manager.arch.memory_endness,
                ins_addr=self._manager.ins_addr,
            )
            stmt = self._set_value(out, res)
        self._statements.append(stmt)

    def _convert_store(self) -> None:
        """
        Convert a p-code store operation
        """
        spc = self._current_op.inputs[0].getSpaceFromConst()
        assert spc.name in {"ram", "mem", "register"}
        if spc.name == "register":
            # store to register
            out = self._current_op.inputs[2]
            res = self._get_value(self._current_op.inputs[1])
            stmt = self._set_value(out, res)
        else:
            # store to memory
            off = self._get_value(self._current_op.inputs[1])
            data = self._get_value(self._current_op.inputs[2])
            log.debug("Storing %s at offset %s", data, off)
            # self.state.memory.store(off, data, endness=self.project.arch.memory_endness)
            stmt = Store(
                self._statement_idx,
                off,
                data,
                self._current_op.inputs[2].size,
                self._manager.arch.memory_endness,
                ins_addr=self._manager.ins_addr,
            )
        self._statements.append(stmt)

    def _convert_branch(self) -> None:
        """
        Convert a p-code branch operation
        """
        if self._current_op.inputs[0].space == "const":
            raise NotImplementedError("p-code relative branch not supported yet")
        dest_addr = self._current_op.inputs[0].offset

        # special handling: if the previous statement is a ConditionalJump with a None destination address, then we
        # back-patch the previous statement
        dest = Const(self._manager.next_atom(), None, dest_addr, self._manager.arch.bits)
        if self._statements:
            last_stmt = self._statements[-1]
            if isinstance(last_stmt, ConditionalJump) and last_stmt.false_target is None:
                last_stmt.false_target = dest
                return

        stmt = Jump(self._statement_idx, dest, ins_addr=self._manager.ins_addr)
        self._statements.append(stmt)

    def _convert_cbranch(self) -> None:
        """
        Convert a p-code conditional branch operation
        """
        if self._current_op.inputs[0].space == "const":
            raise NotImplementedError("p-code relative branch not supported yet")
        dest_addr = self._current_op.inputs[0].offset
        cond = self._get_value(self._current_op.inputs[1])
        cval = Const(self._manager.next_atom(), None, 0, cond.bits)
        condition = BinaryOp(self._manager.next_atom(), "CmpNE", [cond, cval], signed=False)
        dest = Const(self._manager.next_atom(), None, dest_addr, self._manager.arch.bits)
        if self._irsb._ops[-1] is self._current_op:
            # if the cbranch op is the last op, then we need to generate a fallthru target
            fallthru = Const(
                self._manager.next_atom(),
                None,
                self._next_ins_addr,
                self._manager.arch.bits,
            )
        else:
            # there will be a Jump statement that follows the cbranch
            fallthru = None
        stmt = ConditionalJump(self._statement_idx, condition, dest, fallthru, ins_addr=self._manager.ins_addr)
        self._statements.append(stmt)

    def _convert_ret(self) -> None:
        """
        Convert a p-code return operation
        """
        Const(self._manager.next_atom(), None, self._irsb.next, self._manager.arch.bits)
        stmt = Return(
            self._statement_idx,
            [],
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=DEFAULT_STATEMENT,
        )
        self._statements.append(stmt)

    def _convert_branchind(self) -> None:
        """
        Convert a p-code indirect branch operation
        """
        dest = self._get_value(self._current_op.inputs[0])
        stmt = Jump(self._statement_idx, dest, ins_addr=self._manager.ins_addr)
        self._statements.append(stmt)

    def _convert_call(self) -> None:
        """
        Convert a p-code call operation
        """
        ret_reg_offset = self._manager.arch.ret_offset
        if ret_reg_offset is not None:
            ret_expr = Register(None, None, ret_reg_offset, self._manager.arch.bits)  # ???
        else:
            ret_expr = None
        dest = Const(self._manager.next_atom(), None, self._irsb.next, self._manager.arch.bits)
        stmt = Call(
            self._manager.next_atom(),
            dest,
            ret_expr=ret_expr,
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=DEFAULT_STATEMENT,
        )
        self._statements.append(stmt)

    def _convert_callind(self) -> None:
        """
        Convert a p-code indirect call operation
        """
        ret_reg_offset = self._manager.arch.ret_offset
        ret_expr = Register(None, None, ret_reg_offset, self._manager.arch.bits)  # ???
        dest = self._get_value(self._current_op.inputs[0])
        stmt = Call(
            self._manager.next_atom(),
            dest,
            ret_expr=ret_expr,
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=DEFAULT_STATEMENT,
        )
        self._statements.append(stmt)

    def _convert_int2float(self) -> None:
        """
        Convert INT2FLOAT operation.
        """
        out = self._current_op.output
        inp = Convert(
            self._manager.next_atom(),
            self._current_op.inputs[0].size * 8,
            out.size * 8,
            True,
            self._get_value(self._current_op.inputs[0]),
            from_type=Convert.TYPE_INT,
            to_type=Convert.TYPE_FP,
        )
        stmt = self._set_value(out, inp)
        self._statements.append(stmt)

    def _convert_float2float(self) -> None:
        """
        Convert FLOAT2FLOAT operation.
        """
        out = self._current_op.output
        inp = Convert(
            self._manager.next_atom(),
            self._current_op.inputs[0].size * 8,
            out.size * 8,
            True,
            self._get_value(self._current_op.inputs[0]),
            from_type=Convert.TYPE_FP,
            to_type=Convert.TYPE_FP,
        )
        stmt = self._set_value(out, inp)
        self._statements.append(stmt)

    def _convert_callother(self) -> None:
        raise NotImplementedError("CALLOTHER emulation not currently supported")

    def _convert_multiequal(self) -> None:
        raise NotImplementedError("MULTIEQUAL appearing in unheritaged code?")

    def _convert_indirect(self) -> None:
        raise NotImplementedError("INDIRECT appearing in unheritaged code?")

    def _convert_segment_op(self) -> None:
        raise NotImplementedError("SEGMENTOP emulation not currently supported")

    def _convert_cpool_ref(self) -> None:
        raise NotImplementedError("Cannot currently emulate cpool operator")

    def _convert_new(self) -> None:
        raise NotImplementedError("Cannot currently emulate new operator")

import logging

from angr.utils.constants import DEFAULT_STATEMENT
from angr.engines.pcode.lifter import IRSB
import pypcode
from pypcode import OpCode, VarnodeData
from claripy.ast.bv import BV

from .block import Block
from .statement import Statement, Assignment, Store, Jump, ConditionalJump, Return, Call
from .expression import Expression, DirtyExpression, Const, Register, Tmp, UnaryOp, BinaryOp, Load
# FIXME: Convert, ITE
from .manager import Manager
from .converter_common import Converter


l = logging.getLogger(name=__name__)

# FIXME: Not all ops are mapped to AIL expressions!
opcode_to_generic_name = {
    # OpCode.CPUI_MULTIEQUAL        : '',
    # OpCode.CPUI_INDIRECT          : '',
    # OpCode.CPUI_PIECE             : '',
    # OpCode.CPUI_SUBPIECE          : '',
    OpCode.CPUI_INT_EQUAL           : 'CmpEQ',
    OpCode.CPUI_INT_NOTEQUAL        : 'CmpNE',
    OpCode.CPUI_INT_SLESS           : 'CmpLTs',
    OpCode.CPUI_INT_SLESSEQUAL      : 'CmpLEs',
    OpCode.CPUI_INT_LESS            : 'CmpLT',
    OpCode.CPUI_INT_LESSEQUAL       : 'CmpLE',
    # OpCode.CPUI_INT_ZEXT          : '',
    # OpCode.CPUI_INT_SEXT          : '',
    OpCode.CPUI_INT_ADD             : 'Add',
    OpCode.CPUI_INT_SUB             : 'Sub',
    # OpCode.CPUI_INT_CARRY         : '',
    # OpCode.CPUI_INT_SCARRY        : '',
    # OpCode.CPUI_INT_SBORROW       : '',
    # OpCode.CPUI_INT_2COMP         : '',
    # OpCode.CPUI_INT_NEGATE        : '',
    OpCode.CPUI_INT_XOR             : 'Xor',
    OpCode.CPUI_INT_AND             : 'And',
    OpCode.CPUI_INT_OR              : 'Or',
    OpCode.CPUI_INT_LEFT            : 'Shl',
    OpCode.CPUI_INT_RIGHT           : 'Shr',
    OpCode.CPUI_INT_SRIGHT          : 'Sar',
    OpCode.CPUI_INT_MULT            : 'Mul',
    OpCode.CPUI_INT_DIV             : 'Div',
    # OpCode.CPUI_INT_SDIV          : '',
    # OpCode.CPUI_INT_REM           : '',
    # OpCode.CPUI_INT_SREM          : '',
    OpCode.CPUI_BOOL_NEGATE         : 'Not',
    # OpCode.CPUI_BOOL_XOR          : '',
    OpCode.CPUI_BOOL_AND            : 'LogicalAnd',
    OpCode.CPUI_BOOL_OR             : 'LogicalOr',
    # OpCode.CPUI_CAST              : '',
    # OpCode.CPUI_PTRADD            : '',
    # OpCode.CPUI_PTRSUB            : '',
    # OpCode.CPUI_FLOAT_EQUAL       : '',
    # OpCode.CPUI_FLOAT_NOTEQUAL    : '',
    # OpCode.CPUI_FLOAT_LESS        : '',
    # OpCode.CPUI_FLOAT_LESSEQUAL   : '',
    # OpCode.CPUI_FLOAT_NAN         : '',
    # OpCode.CPUI_FLOAT_ADD         : '',
    # OpCode.CPUI_FLOAT_DIV         : '',
    # OpCode.CPUI_FLOAT_MULT        : '',
    # OpCode.CPUI_FLOAT_SUB         : '',
    # OpCode.CPUI_FLOAT_NEG         : '',
    # OpCode.CPUI_FLOAT_ABS         : '',
    # OpCode.CPUI_FLOAT_SQRT        : '',
    # OpCode.CPUI_FLOAT_INT2FLOAT   : '',
    # OpCode.CPUI_FLOAT_FLOAT2FLOAT : '',
    # OpCode.CPUI_FLOAT_TRUNC       : '',
    # OpCode.CPUI_FLOAT_CEIL        : '',
    # OpCode.CPUI_FLOAT_FLOOR       : '',
    # OpCode.CPUI_FLOAT_ROUND       : '',
    # OpCode.CPUI_SEGMENTOP         : '',
    # OpCode.CPUI_CPOOLREF          : '',
    # OpCode.CPUI_NEW               : '',
    # OpCode.CPUI_INSERT            : '',
    # OpCode.CPUI_EXTRACT           : '',
    # OpCode.CPUI_POPCOUNT          : '',
    }


class PCodeIRSBConverter(Converter):
    """
    Converts a P-Code IRSB to an AIL block
    """

    @staticmethod
    def convert(irsb: IRSB, manager: Manager):  # pylint:disable=arguments-differ
        """
        Convert the given IRSB to an AIL block

        :param irsb:    The IRSB to convert
        :param manager: The manager to use
        :return:        Returns the converted block
        """
        return PCodeIRSBConverter(irsb, manager)._convert()

    def __init__(self, irsb: IRSB, manager: Manager):
        self._irsb = irsb
        self._manager = manager
        self._statements = []
        self._current_ins = None
        self._current_op = None
        self._current_behavior = None
        self._statement_idx = 0

        # Remap all uniques s.t. they are write-once with values starting from 0
        self._unique_tracker = {}
        self._unique_counter = 0

        self._special_op_handlers = {
            OpCode.CPUI_COPY:       self._convert_copy,
            OpCode.CPUI_INT_ZEXT:   self._convert_copy,

            OpCode.CPUI_LOAD:       self._convert_load,
            OpCode.CPUI_STORE:      self._convert_store,
            OpCode.CPUI_BRANCH:     self._convert_branch,
            OpCode.CPUI_CBRANCH:    self._convert_cbranch,
            OpCode.CPUI_BRANCHIND:  self._convert_branchind,
            OpCode.CPUI_CALL:       self._convert_call,
            OpCode.CPUI_CALLIND:    self._convert_callind,
            OpCode.CPUI_CALLOTHER:  self._convert_callother,
            OpCode.CPUI_RETURN:     self._convert_ret,
            OpCode.CPUI_MULTIEQUAL: self._convert_multiequal,
            OpCode.CPUI_INDIRECT:   self._convert_indirect,
            OpCode.CPUI_SEGMENTOP:  self._convert_segment_op,
            OpCode.CPUI_CPOOLREF:   self._convert_cpool_ref,
            OpCode.CPUI_NEW:        self._convert_new,
        }

        manager.tyenv = None
        manager.block_addr = irsb.addr
        manager.vex_stmt_idx = DEFAULT_STATEMENT # Reset after loop. Necessary?

    def _convert(self) -> Block:
        """
        Convert the given IRSB to an AIL Block
        """
        self._statement_idx = 0
        for ins in self._irsb._instructions:
            self._current_ins = ins
            self._manager.ins_addr = ins.addr.getOffset()
            for op in self._current_ins.ops:
                self._current_op = op
                opc = self._current_op.getOpcode()
                self._current_behavior = self._irsb.behaviors.get_behavior_for_opcode(opc)
                self._convert_current_op()
                self._statement_idx += 1

        return Block(self._irsb.addr, self._irsb.size, statements=self._statements)

    def _convert_current_op(self) -> None:
        """
        Convert the current op to corresponding AIL statement
        """
        assert self._current_behavior is not None

        is_special = (self._current_behavior.opcode in self._special_op_handlers)

        if is_special:
            self._special_op_handlers[self._current_behavior.opcode]()
        elif self._current_behavior.is_unary:
            self._convert_unary()
        else:
            self._convert_binary()

    def _convert_unary(self) -> None:
        """
        Convert the current unary op to corresponding AIL statement
        """
        opcode = self._current_op.getOpcode()
        op = opcode_to_generic_name.get(opcode, None)
        in1 = self._get_value(self._current_op.getInput(0))

        if op is None:
            expr = pypcode.get_opname(opcode)
            l.warning("P-code: Unsupported opcode of type %s", expr)
            out = DirtyExpression(self._manager.next_atom(), expr,
                                  bits=self._current_op.getOutput().size*8)
        else:
            out = UnaryOp(self._manager.next_atom(), op, in1)

        stmt = self._set_value(self._current_op.getOutput(), out)
        self._statements.append(stmt)

    def _convert_binary(self) -> None:
        """
        Convert the current binary op to corresponding AIL statement
        """
        opcode = self._current_op.getOpcode()
        op = opcode_to_generic_name.get(opcode, None)

        in1 = self._get_value(self._current_op.getInput(0))
        in2 = self._get_value(self._current_op.getInput(1))
        signed = op in {'CmpLEs', 'CmpGTs'}

        if op is None:
            expr = pypcode.get_opname(opcode)
            l.warning("P-Code: Unsupported opcode of type %s.", expr)
            out = DirtyExpression(self._manager.next_atom(), expr,
                                  bits=self._current_op.getOutput().size*8)
        else:
            out = BinaryOp(self._manager.next_atom(), op, [in1, in2], signed)

        stmt = self._set_value(self._current_op.getOutput(), out)
        self._statements.append(stmt)

    def _get_register_name(self, var_data: VarnodeData) -> str:
        """
        Get the register name string for a given varnode

        :param var_data: The varnode to map from
        :return:         The register name
        """
        trans = self._irsb._instructions[0].trans
        return trans.getRegisterName(var_data.space, var_data.offset, var_data.size)

    def _map_register_name(self, var_data: VarnodeData) -> int:
        """
        Map SLEIGH register offset to ArchInfo register offset based on name.

        :param var_data: The varnode to translate
        :return:         The register file offset
        """
        # FIXME: Will need performance optimization
        # FIXME: Should not get trans object this way. Moreover, should have a
        #        faster mapping method than going through trans
        reg_name = self._get_register_name(var_data)
        try:
            reg_offset = self._manager.arch.get_register_offset(reg_name.lower())
            l.debug("Mapped register '%s' to offset %x", reg_name, reg_offset)
        except ValueError:
            reg_offset = var_data.offset + 0x100000
            l.warning("Could not map register '%s' from archinfo. Mapping to %x", reg_name, reg_offset)
        return reg_offset

    def _remap_temp(self, offset: int, is_write: bool) -> int:
        """
        Remap any unique space addresses such that they are written only once

        :param offset:   The unique space address
        :param is_write: Whether the access is a write or a read
        :return:         The remapped temporary register index
        """
        if is_write:
            self._unique_tracker[offset] = self._unique_counter
            self._unique_counter += 1
        else:
            assert(offset in self._unique_tracker)
        return self._unique_tracker[offset]

    def _convert_varnode(self, var_data: VarnodeData, is_write: bool) -> Expression:
        """
        Convert a varnode to a corresponding AIL expression

        :param var_data: The varnode to remap
        :param is_write: Whether the varnode is being read or written to
        :return:         The corresponding AIL expression
        """
        space_name = var_data.space.getName()
        size = var_data.size*8

        if space_name == "const":
            return Const(self._manager.next_atom(), None, var_data.offset, size)
        elif space_name == "register":
            offset = self._map_register_name(var_data)
            return Register(self._manager.next_atom(),
                None, offset, size, reg_name=self._get_register_name(var_data))
        elif space_name == "unique":
            offset = self._remap_temp(var_data.offset, is_write)
            return Tmp(self._manager.next_atom(), None, offset, size)
        elif space_name in ["ram", "mem"]:
            assert(not is_write)
            addr = Const(self._manager.next_atom(),
                None, var_data.offset, self._manager.arch.bits)
            # Note: Load takes bytes, not bits, for size
            return Load(self._manager.next_atom(),
                addr, var_data.size,
                self._manager.arch.memory_endness,
                ins_addr=self._manager.ins_addr)
        else:
            raise NotImplementedError()

    def _set_value(self, var_data: VarnodeData, value: BV) -> Statement:
        """
        Create the appropriate assignment statement to store to a varnode

        This method stores to the appropriate register, or unique space,
        depending on the space indicated by the varnode.

        :param var_data: The varnode to store into
        :param value:    The value to store
        :return:         The corresponding AIL statement
        """
        space_name = var_data.space.getName()

        if space_name in ["register", "unique"]:
            return Assignment(self._statement_idx,
                self._convert_varnode(var_data, True),
                value,
                ins_addr=self._manager.ins_addr)
        elif space_name in ["ram", "mem"]:
            addr = Const(self._manager.next_atom(),
                None, var_data.offset, self._manager.arch.bits)
            return Store(self._statement_idx,
                    addr, value, var_data.size,
                    self._manager.arch.memory_endness,
                    ins_addr=self._manager.ins_addr)
        else:
            raise NotImplementedError()

    def _get_value(self, var_data: VarnodeData) -> Expression:
        """
        Create the appropriate expression to load from a varnode

        This method loads from the appropriate const, register, unique, or RAM
        space, depending on the space indicated by the varnode.

        :param var_data: The varnode to load from.
        :return:         The value loaded
        """
        return self._convert_varnode(var_data, False)

    def _convert_copy(self) -> None:
        """
        Convert copy operation
        """
        out = self._current_op.getOutput()
        inp = self._get_value(self._current_op.getInput(0))
        stmt = self._set_value(out, inp)
        self._statements.append(stmt)

    def _convert_negate(self) -> None:
        """
        Convert bool negate operation
        """
        out = self._current_op.getOutput()
        inp = self._get_value(self._current_op.getInput(0))

        cval = Const(self._manager.next_atom(),
                None, 0, self._current_op.getInput(0).size*8)

        expr = BinaryOp(self._manager.next_atom(), 'CmpEQ', [inp, cval], signed=False)

        stmt = self._set_value(out, expr)
        self._statements.append(stmt)

    def _convert_load(self) -> None:
        """
        Convert a P-code load operation
        """
        spc = pypcode.Address.getSpaceFromConst(self._current_op.getInput(0).getAddr())
        assert spc.getName() in ["ram", "mem"]
        off = self._get_value(self._current_op.getInput(1))
        out = self._current_op.getOutput()
        res = Load(self._manager.next_atom(),
                   off, self._current_op.getInput(1).size, # FIMXE: Check if this is right size
                   self._manager.arch.memory_endness,
                   ins_addr=self._manager.ins_addr)
        stmt = self._set_value(out, res)
        self._statements.append(stmt)

    def _convert_store(self) -> None:
        """
        Convert a P-code store operation
        """
        spc = pypcode.Address.getSpaceFromConst(self._current_op.getInput(0).getAddr())
        assert spc.getName() in ["ram", "mem"]
        off = self._get_value(self._current_op.getInput(1))
        data = self._get_value(self._current_op.getInput(2))
        l.debug("Storing %s at offset %s", data, off)
        #self.state.memory.store(off, data, endness=self.project.arch.memory_endness)
        stmt = Store(self._statement_idx,
                     off, data, self._current_op.getInput(1).size, # FIMXE: Check if this is right size
                     self._manager.arch.memory_endness,
                     ins_addr=self._manager.ins_addr)
        self._statements.append(stmt)

    def _convert_branch(self) -> None:
        """
        Convert a P-code branch operation
        """
        dest_addr = self._current_op.getInput(0).getAddr()
        if dest_addr.isConstant():
            raise NotImplementedError("P-code relative branch not supported yet")
        dest = Const(self._manager.next_atom(),
                None, dest_addr.getOffset(), self._manager.arch.bits)
        stmt = Jump(self._statement_idx, dest, ins_addr=self._manager.ins_addr)
        self._statements.append(stmt)

    def _convert_cbranch(self) -> None:
        """
        Convert a P-code conditional branch operation
        """
        cond = self._get_value(self._current_op.getInput(1))
        dest_addr = self._current_op.getInput(0).getAddr()
        if dest_addr.isConstant():
            raise NotImplementedError("P-code relative branch not supported yet")
        dest_addr = dest_addr.getOffset()
        cval = Const(self._manager.next_atom(), None, 0, cond.bits)
        condition = BinaryOp(self._manager.next_atom(),
                       'CmpNE',
                       [cond, cval],
                       signed=False)
        dest = Const(self._manager.next_atom(),
                None, dest_addr, self._manager.arch.bits)
        fallthru = Const(self._manager.next_atom(),
                None, self._manager.ins_addr + self._current_ins.length,
                self._manager.arch.bits)
        stmt = ConditionalJump(self._statement_idx, condition, dest, fallthru,
                               ins_addr=self._manager.ins_addr)
        self._statements.append(stmt)

    def _convert_ret(self) -> None:
        """
        Convert a P-code return operation
        """
        dest = Const(self._manager.next_atom(),
                None, self._irsb.next, self._manager.arch.bits)
        stmt = Return(self._statement_idx,
            dest, [ ],
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=DEFAULT_STATEMENT,
            )
        self._statements.append(stmt)

    def _convert_branchind(self) -> None:
        """
        Convert a P-code indirect branch operation
        """
        dest = self._get_value(self._current_op.getInput(0))
        stmt = Jump(self._statement_idx, dest, ins_addr=self._manager.ins_addr)
        self._statements.append(stmt)

    def _convert_call(self) -> None:
        """
        Convert a P-code call operation
        """
        ret_reg_offset = self._manager.arch.ret_offset
        ret_expr = Register(None, None, ret_reg_offset, self._manager.arch.bits) # ???
        dest = Const(self._manager.next_atom(),
                    None, self._irsb.next, self._manager.arch.bits)
        stmt = Call(self._manager.next_atom(),
                    dest,
                    ret_expr=ret_expr,
                    ins_addr=self._manager.ins_addr,
                    vex_block_addr=self._manager.block_addr,
                    vex_stmt_idx=DEFAULT_STATEMENT,
                    )
        self._statements.append(stmt)

    def _convert_callind(self) -> None:
        """
        Convert a P-code indirect call operation
        """
        ret_reg_offset = self._manager.arch.ret_offset
        ret_expr = Register(None, None, ret_reg_offset, self._manager.arch.bits) # ???
        dest = self._get_value(self._current_op.getInput(0))
        stmt = Call(self._manager.next_atom(),
                    dest,
                    ret_expr=ret_expr,
                    ins_addr=self._manager.ins_addr,
                    vex_block_addr=self._manager.block_addr,
                    vex_stmt_idx=DEFAULT_STATEMENT,
                    )
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

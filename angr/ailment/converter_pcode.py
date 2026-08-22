from __future__ import annotations

import logging
from collections.abc import Callable

import pypcode
from archinfo import Endness
from pypcode import OpCode, PcodeOp, Varnode

from angr.engines.pcode.lifter import IRSB
from angr.engines.pcode.userop import (
    X86_LOCK_MARKER_USEROP_KEYS,
    X86_PROTECTED_MODE_SEGMENT_USEROP_KEY,
    X86_PROTECTED_MODE_SWI_USEROP_KEY,
    X86_REAL_MODE_ADDRESS_MASK,
    X86_REAL_MODE_SEGMENT_USEROP_KEY,
    X86_REAL_MODE_SWI_USEROP_KEY,
    get_named_userop_key,
    get_x86_segment_varnodes,
    get_x86_swi_varnodes,
    validate_x86_lock_marker,
)
from angr.utils.constants import DEFAULT_STATEMENT

from .block import Block
from .converter_common import Converter
from .expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    DirtyExpression,
    Expression,
    Extract,
    Load,
    Register,
    Reinterpret,
    SegmentedAddress,
    Tmp,
    UnaryOp,
)

# FIXME: Convert, ITE
from .manager import Manager
from .statement import Assignment, ConditionalJump, Jump, Return, SideEffectStatement, Statement, Store

log = logging.getLogger(name=__name__)

# FIXME: Not all ops are mapped to AIL expressions!
opcode_to_generic_name = {
    # OpCode.MULTIEQUAL        : '',
    # OpCode.INDIRECT          : '',
    # OpCode.PIECE             : '',
    # OpCode.SUBPIECE is handled separately because its output is narrower.
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
    # Carry and signed-overflow operations are lowered separately to portable
    # integer expressions instead of leaking p-code intrinsics into C output.
    OpCode.INT_2COMP: "Neg",
    OpCode.INT_NEGATE: "BitwiseNeg",
    OpCode.INT_XOR: "Xor",
    OpCode.INT_AND: "And",
    OpCode.INT_OR: "Or",
    OpCode.INT_LEFT: "Shl",
    OpCode.INT_RIGHT: "Shr",
    OpCode.INT_SRIGHT: "Sar",
    OpCode.INT_MULT: "Mul",
    OpCode.INT_DIV: "Div",
    OpCode.INT_SDIV: "Div",
    OpCode.INT_REM: "Mod",
    OpCode.INT_SREM: "Mod",
    OpCode.BOOL_NEGATE: "Not",
    OpCode.BOOL_XOR: "Xor",
    OpCode.BOOL_AND: "LogicalAnd",
    OpCode.BOOL_OR: "LogicalOr",
    # OpCode.CAST              : '',
    # OpCode.PTRADD            : '',
    # OpCode.PTRSUB            : '',
    OpCode.FLOAT_EQUAL: "CmpEQ",
    OpCode.FLOAT_NOTEQUAL: "CmpNE",
    OpCode.FLOAT_LESS: "CmpLT",
    OpCode.FLOAT_LESSEQUAL: "CmpLE",
    OpCode.FLOAT_NAN: "IsNaN",
    OpCode.FLOAT_ADD: "Add",
    OpCode.FLOAT_DIV: "Div",
    OpCode.FLOAT_MULT: "Mul",
    OpCode.FLOAT_SUB: "Sub",
    OpCode.FLOAT_NEG: "Neg",
    OpCode.FLOAT_ABS: "Abs",
    OpCode.FLOAT_SQRT: "Sqrt",
    # OpCode.FLOAT_INT2FLOAT   : '',
    # OpCode.FLOAT_FLOAT2FLOAT : '',
    # FLOAT_TRUNC is handled separately because it converts from FP to INT.
    OpCode.FLOAT_CEIL: "Ceil",
    OpCode.FLOAT_FLOOR: "Floor",
    OpCode.FLOAT_ROUND: "Round",
    # OpCode.SEGMENTOP         : '',
    # OpCode.CPOOLREF          : '',
    # OpCode.NEW               : '',
    # OpCode.INSERT            : '',
    # OpCode.ZPULL             : '',
    # OpCode.SPULL             : '',
    OpCode.POPCOUNT: "PopCount",
}


_X86_16_SWI_INPUT_REGISTERS = ("ax", "bx", "cx", "dx", "si", "di", "ds", "es")
_X86_16_SWI_INPUT_FLAGS = ("cf", "pf", "af", "zf", "sf", "of", "df")


class PCodeIRSBConverter(Converter):
    """
    Converts a p-code IRSB to an AIL block
    """

    _current_op: PcodeOp

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
        self._next_ins_addr = None
        self._current_behavior = None
        self._statement_idx = 0
        self._current_instruction_statement_start = 0
        self._current_instruction_op_start = 0
        self._current_op_index = 0

        # Remap all uniques s.t. they are write-once with values starting from 0
        self._unique_tracker: dict[int, tuple[int, int]] = {}
        self._unique_counter = 0

        self._special_op_handlers = {
            OpCode.COPY: self._convert_copy,
            OpCode.INT_ZEXT: self._convert_zext,
            OpCode.INT_SEXT: self._convert_sext,
            OpCode.SUBPIECE: self._convert_subpiece,
            OpCode.INT_CARRY: self._convert_int_carry,
            OpCode.INT_SCARRY: self._convert_int_scarry,
            OpCode.INT_SBORROW: self._convert_int_sborrow,
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
            OpCode.FLOAT_TRUNC: self._convert_float_trunc,
        }
        self._swi_targets: dict[tuple[str, int, int], int] = {}
        self._segmented_addresses: dict[tuple[str, int, int], SegmentedAddress] = {}
        # Track exact register-to-register copies inside this IRSB. This is deliberately local to one basic block:
        # it lets a later protected-mode segment operation retain facts such as ``mov ax, ss; mov es, ax`` without
        # guessing across control-flow joins or calls. A write through any overlapping register invalidates the
        # corresponding fact.
        self._register_origins: dict[tuple[int, int], str] = {}
        self._modified_register_bytes: set[int] = set()

        manager.tyenv = None
        manager.block_addr = irsb.addr
        manager.vex_stmt_idx = DEFAULT_STATEMENT  # Reset after loop. Necessary?

    def _convert(self) -> Block:
        """
        Convert the given IRSB to an AIL Block
        """
        self._statement_idx = 0

        for op_index, op in enumerate(self._irsb._ops):
            self._current_op_index = op_index
            self._current_op = op
            if op.opcode == pypcode.OpCode.IMARK:
                self._current_instruction_statement_start = len(self._statements)
                self._current_instruction_op_start = op_index + 1
                self._manager.ins_addr = op.inputs[0].offset
                self._next_ins_addr = op.inputs[-1].offset + op.inputs[-1].size
            else:
                assert self._irsb.behaviors is not None
                self._current_behavior = self._irsb.behaviors.get_behavior_for_opcode(self._current_op.opcode)
                self._convert_current_op()
            self._statement_idx += 1

            if (
                "sparc:" in self._irsb.arch.name
                and self._irsb.arch.bits == 32
                and self._current_op.opcode == OpCode.CALL
            ):
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
                self._preserve_unsupported_output()
        elif self._current_behavior.is_unary:
            self._convert_unary()
        else:
            self._convert_binary()

    def _preserve_unsupported_output(self) -> None:
        """
        Preserve the data flow of an unsupported p-code operation.

        Unsupported operations with an output may feed later operations in the
        same block. Represent the unknown result as a dirty expression so the
        output varnode is still defined and its inputs remain visible to AIL
        analyses.
        """
        output = self._current_op.output
        if output is None:
            return

        operands = [self._get_value(varnode) for varnode in self._current_op.inputs]
        value = DirtyExpression(
            self._manager.next_atom(),
            self._current_op.opcode.name,
            operands,
            bits=output.size * 8,
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=self._statement_idx,
        )
        self._statements.append(self._set_value(output, value))

    def _convert_unary(self) -> None:
        """
        Convert the current unary op to corresponding AIL statement
        """
        opcode = self._current_op.opcode

        op = opcode_to_generic_name.get(opcode)
        float_opcodes = {
            OpCode.FLOAT_NEG,
            OpCode.FLOAT_ABS,
            OpCode.FLOAT_SQRT,
            OpCode.FLOAT_NAN,
            OpCode.FLOAT_CEIL,
            OpCode.FLOAT_FLOOR,
            OpCode.FLOAT_ROUND,
        }
        is_float = opcode in float_opcodes
        in1 = (
            self._reinterpret_as_float(self._current_op.inputs[0])
            if is_float
            else self._get_value(self._current_op.inputs[0])
        )
        if op is None:
            log.warning("p-code: Unsupported opcode of type %s", opcode.__name__)
            out = DirtyExpression(
                self._manager.next_atom(),
                opcode.__name__,
                [in1],
                bits=self._current_op.output.size * 8 if self._current_op.output is not None else 1,
                ins_addr=self._manager.ins_addr,
                vex_block_addr=self._manager.block_addr,
                vex_stmt_idx=self._statement_idx,
            )
        else:
            out = UnaryOp(
                self._manager.next_atom(),
                op,
                in1,
                bits=1 if opcode == OpCode.FLOAT_NAN else self._current_op.output.size * 8,
                ins_addr=self._manager.ins_addr,
            )

            if is_float and opcode != OpCode.FLOAT_NAN:
                out = self._reinterpret_float_as_bits(out, self._current_op.output.size * 8)

            if opcode == OpCode.FLOAT_NAN and self._current_op.output.size * 8 != 1:
                out = Convert(
                    self._manager.next_atom(),
                    1,
                    self._current_op.output.size * 8,
                    False,
                    out,
                )

        stmt = self._set_value(self._current_op.output, out)
        self._statements.append(stmt)

    def _convert_binary(self) -> None:
        """
        Convert the current binary op to corresponding AIL statement
        """
        opcode = self._current_op.opcode
        op = opcode_to_generic_name.get(opcode)
        float_opcodes = {
            OpCode.FLOAT_EQUAL,
            OpCode.FLOAT_NOTEQUAL,
            OpCode.FLOAT_LESS,
            OpCode.FLOAT_LESSEQUAL,
            OpCode.FLOAT_ADD,
            OpCode.FLOAT_DIV,
            OpCode.FLOAT_MULT,
            OpCode.FLOAT_SUB,
        }
        is_float = opcode in float_opcodes
        if is_float:
            in1 = self._reinterpret_as_float(self._current_op.inputs[0])
            in2 = self._reinterpret_as_float(self._current_op.inputs[1])
        else:
            in1 = self._get_value(self._current_op.inputs[0])
            in2 = self._get_value(self._current_op.inputs[1])
        if op is None:
            log.warning("p-code: Unsupported opcode of type %s.", opcode.__name__)
            out = DirtyExpression(
                self._manager.next_atom(),
                opcode.__name__,
                [in1, in2],
                bits=self._current_op.output.size * 8 if self._current_op.output is not None else 1,
                ins_addr=self._manager.ins_addr,
                vex_block_addr=self._manager.block_addr,
                vex_stmt_idx=self._statement_idx,
            )
        else:
            # fix op name for signed comparisons
            signed = opcode in {
                OpCode.INT_SLESS,
                OpCode.INT_SLESSEQUAL,
                OpCode.INT_SDIV,
                OpCode.INT_SREM,
            }
            if op.startswith("Cmp") and op.endswith("s"):
                op = op[:-1]
            out = BinaryOp(
                self._manager.next_atom(),
                op,
                [in1, in2],
                signed,
                bits=None if op.startswith("Cmp") else self._current_op.output.size * 8,
                floating_point=is_float,
                ins_addr=self._manager.ins_addr,
            )
            if is_float and not op.startswith("Cmp"):
                out = self._reinterpret_float_as_bits(out, self._current_op.output.size * 8)

        # Zero-extend 1-bit results
        zextend_ops = {
            OpCode.INT_EQUAL,
            OpCode.INT_NOTEQUAL,
            OpCode.INT_SLESS,
            OpCode.INT_SLESSEQUAL,
            OpCode.INT_LESS,
            OpCode.INT_LESSEQUAL,
            OpCode.FLOAT_EQUAL,
            OpCode.FLOAT_NOTEQUAL,
            OpCode.FLOAT_LESS,
            OpCode.FLOAT_LESSEQUAL,
        }
        if opcode in zextend_ops:
            out = Convert(self._manager.next_atom(), 1, self._current_op.output.size * 8, False, out)

        if self._remember_segmented_address_arithmetic(opcode, in1, in2):
            return

        stmt = self._set_value(self._current_op.output, out)
        self._statements.append(stmt)

    def _convert_subpiece(self) -> None:
        output = self._current_op.output
        if output is None or len(self._current_op.inputs) != 2:
            raise NotImplementedError("SUBPIECE must have an output and two operands")

        base_varnode, offset_varnode = self._current_op.inputs
        offset = self._get_value(offset_varnode)
        if not isinstance(offset, Const) or not isinstance(offset.value, int):
            raise NotImplementedError("SUBPIECE byte offset must be constant")

        byte_offset = offset.value
        if self._irsb.arch.memory_endness == Endness.BE:
            byte_offset = base_varnode.size - output.size - byte_offset
        if byte_offset < 0 or byte_offset + output.size > base_varnode.size:
            raise NotImplementedError("SUBPIECE selects bytes outside its input")

        tags = {
            "ins_addr": self._manager.ins_addr,
            "vex_block_addr": self._manager.block_addr,
            "vex_stmt_idx": self._statement_idx,
        }
        value = Extract(
            self._manager.next_atom(),
            output.size * 8,
            self._get_value(base_varnode),
            Const(self._manager.next_atom(), byte_offset, offset.bits),
            self._irsb.arch.memory_endness,
            **tags,
        )
        self._statements.append(self._set_value(output, value))

    def _unsigned(self, expr: Expression, bits: int, tags: dict) -> Convert:
        return Convert(self._manager.next_atom(), bits, bits, False, expr, **tags)

    def _wrap_unsigned(self, expr: Expression, bits: int, tags: dict) -> Convert:
        return Convert(self._manager.next_atom(), bits, bits, False, expr, **tags)

    def _write_flag(self, flag: Expression, flag_bits: int) -> None:
        output = self._current_op.output
        if output is None:
            raise NotImplementedError(f"{self._current_op.opcode.name} must have an output")
        output_bits = output.size * 8
        value = (
            flag
            if flag_bits == output_bits
            else Convert(
                self._manager.next_atom(),
                flag_bits,
                output_bits,
                False,
                flag,
                ins_addr=self._manager.ins_addr,
            )
        )
        self._statements.append(self._set_value(output, value))

    def _integer_flag_operands(self) -> tuple[Expression, Expression, int, dict]:
        output = self._current_op.output
        if output is None or len(self._current_op.inputs) != 2:
            raise NotImplementedError(f"{self._current_op.opcode.name} must have an output and two operands")
        left_varnode, right_varnode = self._current_op.inputs
        if left_varnode.size != right_varnode.size:
            raise NotImplementedError(f"{self._current_op.opcode.name} operands must have matching widths")
        bits = left_varnode.size * 8
        tags = {
            "ins_addr": self._manager.ins_addr,
            "vex_block_addr": self._manager.block_addr,
            "vex_stmt_idx": self._statement_idx,
        }
        return (
            self._unsigned(self._get_value(left_varnode), bits, tags),
            self._unsigned(self._get_value(right_varnode), bits, tags),
            bits,
            tags,
        )

    def _convert_int_carry(self) -> None:
        left, right, bits, tags = self._integer_flag_operands()
        total = BinaryOp(self._manager.next_atom(), "Add", [left, right], signed=False, bits=bits, **tags)
        wrapped = self._wrap_unsigned(total, bits, tags)
        carry = BinaryOp(self._manager.next_atom(), "CmpLT", [wrapped, left], signed=False, bits=1, **tags)
        self._write_flag(carry, 1)

    def _convert_int_scarry(self) -> None:
        left, right, bits, tags = self._integer_flag_operands()
        total = BinaryOp(self._manager.next_atom(), "Add", [left, right], signed=False, bits=bits, **tags)
        wrapped = self._wrap_unsigned(total, bits, tags)
        same_sign = UnaryOp(
            self._manager.next_atom(),
            "BitwiseNeg",
            BinaryOp(self._manager.next_atom(), "Xor", [left, right], signed=False, bits=bits, **tags),
            bits=bits,
            **tags,
        )
        changed_sign = BinaryOp(self._manager.next_atom(), "Xor", [left, wrapped], signed=False, bits=bits, **tags)
        overflow_bits = BinaryOp(
            self._manager.next_atom(), "And", [same_sign, changed_sign], signed=False, bits=bits, **tags
        )
        self._write_sign_bit(overflow_bits, bits, tags)

    def _convert_int_sborrow(self) -> None:
        left, right, bits, tags = self._integer_flag_operands()
        difference = BinaryOp(self._manager.next_atom(), "Sub", [left, right], signed=False, bits=bits, **tags)
        wrapped = self._wrap_unsigned(difference, bits, tags)
        different_signs = BinaryOp(self._manager.next_atom(), "Xor", [left, right], signed=False, bits=bits, **tags)
        changed_sign = BinaryOp(self._manager.next_atom(), "Xor", [left, wrapped], signed=False, bits=bits, **tags)
        overflow_bits = BinaryOp(
            self._manager.next_atom(), "And", [different_signs, changed_sign], signed=False, bits=bits, **tags
        )
        self._write_sign_bit(overflow_bits, bits, tags)

    def _write_sign_bit(self, value: Expression, bits: int, tags: dict) -> None:
        shifted = BinaryOp(
            self._manager.next_atom(),
            "Shr",
            [value, Const(self._manager.next_atom(), bits - 1, bits)],
            signed=False,
            bits=bits,
            **tags,
        )
        flag = BinaryOp(
            self._manager.next_atom(),
            "And",
            [shifted, Const(self._manager.next_atom(), 1, bits)],
            signed=False,
            bits=bits,
            **tags,
        )
        self._write_flag(flag, bits)

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

    def _remap_temp(self, offset: int, size: int, is_write: bool) -> int | None:
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
            return Const(self._manager.next_atom(), varnode.offset, size)
        if space_name == "register":
            offset = self._map_register_name(varnode)
            return Register(
                self._manager.next_atom(),
                offset,
                size,
                reg_name=varnode.getRegisterName(),
                ins_addr=self._manager.ins_addr,
            )
        if space_name == "unique":
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
                t = Tmp(self._manager.next_atom(), unique_offset, ori_tmp_size * 8)
                # FIXME: Asserting BE
                right_shift_amount = varnode.offset + varnode.size - (unique_offset + ori_tmp_size)
                if right_shift_amount != 0:
                    t = BinaryOp(
                        self._manager.next_atom(),
                        "Shr",
                        [t, Const(self._manager.next_atom(), right_shift_amount * 8, 8)],
                        False,
                        ins_addr=self._manager.ins_addr,
                    )
                return Convert(self._manager.next_atom(), t.bits, size, False, t, ins_addr=self._manager.ins_addr)

            return Tmp(self._manager.next_atom(), offset, size)
        if space_name.lower() in ["ram", "mem"]:
            assert not is_write
            addr = Const(self._manager.next_atom(), varnode.offset, self._manager.arch.bits)
            # Note: Load takes bytes, not bits, for size
            return Load(
                self._manager.next_atom(),
                addr,
                varnode.size,
                self._manager.arch.memory_endness,
                ins_addr=self._manager.ins_addr,
            )
        raise NotImplementedError

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

        # P-code unique offsets are scratch storage and may be reused. A remembered segmented address is valid only
        # until the exact varnode is overwritten by an ordinary operation.
        self._segmented_addresses.pop(self._varnode_key(varnode), None)

        if space_name == "register":
            self._invalidate_register_origin(varnode)

        if space_name in ["register", "unique"]:
            return Assignment(
                self._statement_idx, self._convert_varnode(varnode, True), value, ins_addr=self._manager.ins_addr
            )
        if space_name.lower() in ["ram", "mem"]:
            addr = Const(self._manager.next_atom(), varnode.offset, self._manager.arch.bits)
            return Store(
                self._statement_idx,
                addr,
                value,
                varnode.size,
                self._manager.arch.memory_endness,
                ins_addr=self._manager.ins_addr,
            )
        raise NotImplementedError

    def _get_value(self, varnode: Varnode) -> Expression:
        """
        Create the appropriate expression to load from a varnode

        This method loads from the appropriate const, register, unique, or RAM
        space, depending on the space indicated by the varnode.

        :param varnode: Varnode to load from.
        :return:        Value loaded
        """
        segmented_address = getattr(self, "_segmented_addresses", {}).get(self._varnode_key(varnode))
        if segmented_address is not None:
            return segmented_address.copy()
        return self._convert_varnode(varnode, False)

    def _convert_copy(self) -> None:
        """
        Convert copy operation
        """
        out = self._current_op.output
        input_varnode = self._current_op.inputs[0]
        inp = self._get_value(input_varnode)

        if out.space.name == "unique" and isinstance(inp, SegmentedAddress):
            self._segmented_addresses[self._varnode_key(out)] = inp.copy()
            return

        register_origin = self._register_origin(input_varnode) if out.space.name == "register" else None
        stmt = self._set_value(out, inp)
        self._statements.append(stmt)
        if register_origin is not None:
            self._register_origins[(out.offset, out.size)] = register_origin

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
            True,
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

        cval = Const(self._manager.next_atom(), 0, self._current_op.inputs[0].size * 8)

        expr = BinaryOp(self._manager.next_atom(), "CmpEQ", [inp, cval], signed=False, ins_addr=self._manager.ins_addr)

        stmt = self._set_value(out, expr)
        self._statements.append(stmt)

    def _convert_load(self) -> None:
        """
        Convert a p-code load operation
        """
        spc = self._current_op.inputs[0].getSpaceFromConst()
        out = self._current_op.output
        spc_name = spc.name.lower()
        assert spc_name in {"ram", "mem", "register"}
        if spc_name == "register":
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
        spc_name = spc.name.lower()
        assert spc_name in {"ram", "mem", "register"}
        if spc_name == "register":
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

    def _current_instruction(self):
        disassembly = self._irsb.disassembly
        if disassembly is None:
            return None
        return next(
            (insn for insn in disassembly.insns if insn.address == self._manager.ins_addr),
            None,
        )

    def _x86_control_transfer_kind(self, near_mnemonic: str, far_mnemonic: str) -> str:
        """Recover the x86 near/far distinction that p-code opcodes erase."""
        if not self._irsb.arch.name.lower().startswith("x86:"):
            return "unknown"
        instruction = self._current_instruction()
        if instruction is None:
            return "unknown"
        mnemonic = instruction.mnemonic.upper()
        if mnemonic == near_mnemonic:
            return "near"
        if mnemonic == far_mnemonic:
            return "far"
        return "unknown"

    def _direct_control_transfer_target(self, dest_addr: int, transfer_kind: str) -> Expression:
        """Build a direct target without flattening a protected-mode 16:16 address."""
        instruction = self._current_instruction()
        if transfer_kind == "far" and self._irsb.arch.name == "x86:LE:16:Protected Mode" and instruction is not None:
            if instruction.size == 5:
                selector_value = (dest_addr >> 16) & 0xFFFF
                offset_value = dest_addr & 0xFFFF
                offset_bits = 16
            elif instruction.size == 8:
                selector_write = next(
                    (
                        op
                        for op in reversed(self._irsb._ops[self._current_instruction_op_start : self._current_op_index])
                        if op.opcode == OpCode.COPY
                        and op.output is not None
                        and op.output.getRegisterName() == "CS"
                        and op.inputs
                        and op.inputs[0].space.name == "const"
                    ),
                    None,
                )
                if selector_write is None:
                    return Const(self._manager.next_atom(), dest_addr, self._manager.arch.bits)
                selector_value = selector_write.inputs[0].offset & 0xFFFF
                offset_value = dest_addr & 0xFFFFFFFF
                offset_bits = 32
            else:
                return Const(self._manager.next_atom(), dest_addr, self._manager.arch.bits)
            return SegmentedAddress(
                self._manager.next_atom(),
                Const(self._manager.next_atom(), selector_value, 16),
                Const(self._manager.next_atom(), offset_value, offset_bits),
                f"x86-protected-16:{offset_bits}",
                bits=32,
                ins_addr=self._manager.ins_addr,
                vex_block_addr=self._manager.block_addr,
                vex_stmt_idx=self._statement_idx,
            )
        return Const(self._manager.next_atom(), dest_addr, self._manager.arch.bits)

    def _discard_x86_control_transfer_setup(self, *, is_call: bool) -> None:
        """Remove p-code's inline control-transfer setup from the current instruction.

        AIL represents the transfer as one semantic node. Leaving the synthetic
        CS/SP writes and return-frame stores beside it would both duplicate that
        operation and, for segmented executables, confuse analysis-time selector
        values with runtime selectors.
        """
        kept = []
        for statement in self._statements[self._current_instruction_statement_start :]:
            if is_call and isinstance(statement, Store):
                continue
            if isinstance(statement, Assignment) and isinstance(statement.dst, Register):
                register_name = statement.dst.tags.get("reg_name", "").lower()
                if register_name == "cs" or (is_call and register_name in {"sp", "esp", "rsp"}):
                    continue
            kept.append(statement)
        self._statements[self._current_instruction_statement_start :] = kept

    def _discard_x86_return_setup(self) -> None:
        """Remove p-code's inline return-frame manipulation from the current instruction.

        An AIL ``Return`` represents the complete machine return. The IP/CS
        loads and stack-pointer updates emitted by SLEIGH are implementation
        details of that transfer, not ordinary function-body memory accesses.
        Return-address width and immediate stack cleanup remain available from
        the decoded instruction to calling-convention and stack analyses.
        """
        del self._statements[self._current_instruction_statement_start :]

    def _convert_branch(self) -> None:
        """
        Convert a p-code branch operation
        """
        if self._current_op.inputs[0].space == "const":
            raise NotImplementedError("p-code relative branch not supported yet")
        dest_addr = self._current_op.inputs[0].offset

        # special handling: if the previous statement is a ConditionalJump with a None destination address, then we
        # back-patch the previous statement
        transfer_kind = self._x86_control_transfer_kind("JMP", "JMPF")
        dest = self._direct_control_transfer_target(dest_addr, transfer_kind)
        if transfer_kind != "unknown":
            self._discard_x86_control_transfer_setup(is_call=False)
        if self._statements:
            last_stmt = self._statements[-1]
            if isinstance(last_stmt, ConditionalJump) and last_stmt.false_target is None:
                last_stmt.false_target = dest
                return

        stmt = Jump(
            self._statement_idx,
            dest,
            transfer_kind=transfer_kind,
            ins_addr=self._manager.ins_addr,
        )
        self._statements.append(stmt)

    def _convert_cbranch(self) -> None:
        """
        Convert a p-code conditional branch operation
        """
        if self._current_op.inputs[0].space == "const":
            raise NotImplementedError("p-code relative branch not supported yet")
        dest_addr = self._current_op.inputs[0].offset
        cond = self._get_value(self._current_op.inputs[1])
        cval = Const(self._manager.next_atom(), 0, cond.bits)
        condition = BinaryOp(self._manager.next_atom(), "CmpNE", [cond, cval], signed=False)
        dest = Const(self._manager.next_atom(), dest_addr, self._manager.arch.bits)
        if self._irsb._ops[-1] is self._current_op:
            # if the cbranch op is the last op, then we need to generate a fallthru target
            fallthru = Const(
                self._manager.next_atom(),
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
        return_kind = self._x86_control_transfer_kind("RET", "RETF")
        if return_kind != "unknown":
            self._discard_x86_return_setup()
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
        transfer_kind = self._x86_control_transfer_kind("JMP", "JMPF")
        if transfer_kind != "unknown":
            self._discard_x86_control_transfer_setup(is_call=False)
        stmt = Jump(
            self._statement_idx,
            dest,
            transfer_kind=transfer_kind,
            ins_addr=self._manager.ins_addr,
        )
        self._statements.append(stmt)

    def _convert_call(self) -> None:
        """
        Convert a p-code call operation
        """
        ret_reg_offset = self._manager.arch.ret_offset
        ret_expr = (
            None
            if ret_reg_offset is None
            else Register(
                self._manager.next_atom(),
                ret_reg_offset,
                self._manager.arch.bits,
                ins_addr=self._manager.ins_addr,
            )
        )  # ???
        transfer_kind = self._x86_control_transfer_kind("CALL", "CALLF")
        dest = self._direct_control_transfer_target(self._current_op.inputs[0].offset, transfer_kind)
        if transfer_kind != "unknown":
            self._discard_x86_control_transfer_setup(is_call=True)
        call_expr = Call(
            self._manager.next_atom(),
            dest,
            transfer_kind=transfer_kind,
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=DEFAULT_STATEMENT,
        )
        stmt = SideEffectStatement(
            self._manager.next_atom(),
            call_expr,
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
        ret_expr = Register(
            self._manager.next_atom(),
            ret_reg_offset,
            self._manager.arch.bits,
            ins_addr=self._manager.ins_addr,
        )  # ???
        target_varnode = self._current_op.inputs[0]
        swi_vector = self._swi_targets.pop(self._varnode_key(target_varnode), None)
        if swi_vector is None:
            dest = self._get_value(target_varnode)
            args = None
        else:
            dest = "__pcode_swi"
            args = self._x86_swi_call_arguments(swi_vector)
        transfer_kind = self._x86_control_transfer_kind("CALL", "CALLF")
        if transfer_kind != "unknown":
            self._discard_x86_control_transfer_setup(is_call=True)
        call_expr = Call(
            self._manager.next_atom(),
            dest,
            args=args,
            transfer_kind=transfer_kind,
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=DEFAULT_STATEMENT,
        )
        stmt = SideEffectStatement(
            self._manager.next_atom(),
            call_expr,
            ret_expr=ret_expr,
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=DEFAULT_STATEMENT,
        )
        self._statements.append(stmt)

    def _x86_swi_call_arguments(self, vector: int) -> list[Expression]:
        """Preserve the machine register state consumed by an x86-16 software interrupt runtime."""
        args: list[Expression] = [Const(self._manager.next_atom(), vector, 8, ins_addr=self._manager.ins_addr)]
        for register_name in _X86_16_SWI_INPUT_REGISTERS:
            try:
                register_offset, register_size = self._manager.arch.registers[register_name]
            except KeyError as ex:
                raise NotImplementedError(
                    f"x86-16 software-interrupt register {register_name!r} is missing from the architecture"
                ) from ex
            if register_size != 2:
                raise NotImplementedError(
                    f"x86-16 software-interrupt register {register_name!r} has unexpected size {register_size}"
                )
            args.append(
                Register(
                    self._manager.next_atom(),
                    register_offset,
                    register_size * self._manager.arch.byte_width,
                    reg_name=register_name,
                    ins_addr=self._manager.ins_addr,
                )
            )
        for register_name in _X86_16_SWI_INPUT_FLAGS:
            try:
                register_offset, register_size = self._manager.arch.registers[register_name]
            except KeyError as ex:
                raise NotImplementedError(
                    f"x86-16 software-interrupt flag {register_name!r} is missing from the architecture"
                ) from ex
            if register_size != 1:
                raise NotImplementedError(
                    f"x86-16 software-interrupt flag {register_name!r} has unexpected size {register_size}"
                )
            args.append(
                Register(
                    self._manager.next_atom(),
                    register_offset,
                    register_size * self._manager.arch.byte_width,
                    reg_name=register_name,
                    ins_addr=self._manager.ins_addr,
                )
            )
        return args

    def _convert_int2float(self) -> None:
        """
        Convert INT2FLOAT operation.
        """
        out = self._current_op.output
        converted = Convert(
            self._manager.next_atom(),
            self._current_op.inputs[0].size * 8,
            out.size * 8,
            True,
            self._get_value(self._current_op.inputs[0]),
            from_type=Convert.TYPE_INT,
            to_type=Convert.TYPE_FP,
        )
        stmt = self._set_value(out, self._reinterpret_float_as_bits(converted, out.size * 8))
        self._statements.append(stmt)

    def _convert_float2float(self) -> None:
        """
        Convert FLOAT2FLOAT operation.
        """
        out = self._current_op.output
        converted = Convert(
            self._manager.next_atom(),
            self._current_op.inputs[0].size * 8,
            out.size * 8,
            True,
            self._reinterpret_as_float(self._current_op.inputs[0]),
            from_type=Convert.TYPE_FP,
            to_type=Convert.TYPE_FP,
        )
        stmt = self._set_value(out, self._reinterpret_float_as_bits(converted, out.size * 8))
        self._statements.append(stmt)

    def _convert_float_trunc(self) -> None:
        """Convert a p-code floating-point value to a signed integer, truncating toward zero."""

        out = self._current_op.output
        inp = Convert(
            self._manager.next_atom(),
            self._current_op.inputs[0].size * 8,
            out.size * 8,
            True,
            self._reinterpret_as_float(self._current_op.inputs[0]),
            from_type=Convert.TYPE_FP,
            to_type=Convert.TYPE_INT,
        )
        stmt = self._set_value(out, inp)
        self._statements.append(stmt)

    def _reinterpret_as_float(self, varnode: Varnode) -> Reinterpret:
        bits = varnode.size * 8
        return Reinterpret(
            self._manager.next_atom(),
            bits,
            "I",
            bits,
            "F",
            self._get_value(varnode),
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=self._statement_idx,
        )

    def _reinterpret_float_as_bits(self, value: Expression, bits: int) -> Reinterpret:
        return Reinterpret(
            self._manager.next_atom(),
            bits,
            "F",
            bits,
            "I",
            value,
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=self._statement_idx,
        )

    def _convert_callother(self) -> None:
        try:
            key = get_named_userop_key(self._irsb.arch.name, self._current_op)
        except ValueError as ex:
            raise NotImplementedError(f"Invalid CALLOTHER operation: {ex}") from ex

        handlers: dict[tuple[str, str], Callable[[], None]] = {
            X86_REAL_MODE_SEGMENT_USEROP_KEY: self._convert_x86_real_mode_segment,
            X86_PROTECTED_MODE_SEGMENT_USEROP_KEY: self._convert_x86_protected_mode_segment,
            X86_REAL_MODE_SWI_USEROP_KEY: self._convert_x86_swi,
            X86_PROTECTED_MODE_SWI_USEROP_KEY: self._convert_x86_swi,
        }
        handler = handlers.get(key)
        if key in X86_LOCK_MARKER_USEROP_KEYS:
            try:
                validate_x86_lock_marker(self._current_op)
            except ValueError as ex:
                raise NotImplementedError(f"Invalid x86 lock marker: {ex}") from ex
            return
        if handler is None:
            language_id, name = key
            raise NotImplementedError(f"CALLOTHER userop {name!r} is not supported for p-code language {language_id!r}")
        handler()

    @staticmethod
    def _varnode_key(varnode: Varnode) -> tuple[str, int, int]:
        return varnode.space.name, varnode.offset, varnode.size

    def _invalidate_register_origin(self, varnode: Varnode) -> None:
        """Forget exact copy provenance after a register write.

        P-code exposes overlapping names such as AX, AH, and AL as ranges in one register space. Invalidating by
        range keeps a partial write from leaving a stale full-register equality behind.
        """

        start = varnode.offset
        end = start + varnode.size
        for key_start, key_size in tuple(self._register_origins):
            if key_start < end and start < key_start + key_size:
                del self._register_origins[(key_start, key_size)]
        self._modified_register_bytes.update(range(start, end))

    def _register_origin(self, varnode: Varnode) -> str | None:
        """Return an exact same-block copy origin for one register varnode."""

        if varnode.space.name != "register":
            return None
        key = varnode.offset, varnode.size
        if key in self._register_origins:
            return self._register_origins[key]
        if any(
            offset in self._modified_register_bytes for offset in range(varnode.offset, varnode.offset + varnode.size)
        ):
            return None
        register_name = varnode.getRegisterName()
        return register_name.lower() if register_name else None

    def _remember_segmented_address_arithmetic(
        self,
        opcode: OpCode,
        left: Expression,
        right: Expression,
    ) -> bool:
        """Keep constant 16-bit effective-address displacement inside a segmented address.

        SLEIGH represents multi-field x86 stores such as FSTENV as one SEGMENTOP followed by constant additions to
        its internal 32-bit address-space value. Emitting those intermediates as ordinary integer temporaries loses
        the selector. For protected 16:16 addresses, preserve the selector and apply the displacement to the 16-bit
        effective offset instead. Other address arithmetic remains explicit and therefore fails closed downstream.
        """

        output = self._current_op.output
        if output is None or output.space.name != "unique" or opcode not in {OpCode.INT_ADD, OpCode.INT_SUB}:
            return False

        address: SegmentedAddress | None = None
        displacement: Const | None = None
        operation = "Add"
        if isinstance(left, SegmentedAddress) and isinstance(right, Const):
            address = left
            displacement = right
            operation = "Sub" if opcode == OpCode.INT_SUB else "Add"
        elif opcode == OpCode.INT_ADD and isinstance(right, SegmentedAddress) and isinstance(left, Const):
            address = right
            displacement = left

        if (
            address is None
            or displacement is None
            or address.address_kind != "x86-protected-16:16"
            or address.bits != output.size * 8
            or address.selector.bits != 16
            or address.offset.bits != 16
            or not isinstance(displacement.value, int)
        ):
            return False

        tags = {
            "ins_addr": self._manager.ins_addr,
            "vex_block_addr": self._manager.block_addr,
            "vex_stmt_idx": self._statement_idx,
        }
        offset_displacement = Const(
            self._manager.next_atom(),
            displacement.value & 0xFFFF,
            address.offset.bits,
            **tags,
        )
        offset = BinaryOp(
            self._manager.next_atom(),
            operation,
            [address.offset.copy(), offset_displacement],
            signed=False,
            bits=address.offset.bits,
            **tags,
        )
        self._segmented_addresses[self._varnode_key(output)] = SegmentedAddress(
            self._manager.next_atom(),
            address.selector.copy(),
            offset,
            address.address_kind,
            bits=address.bits,
            **(address.tags | tags),
        )
        return True

    def _convert_x86_swi(self) -> None:
        try:
            output, vector = get_x86_swi_varnodes(self._current_op)
        except ValueError as ex:
            raise NotImplementedError(f"Invalid x86 software-interrupt userop: {ex}") from ex
        self._swi_targets[self._varnode_key(output)] = vector.offset

    def _convert_x86_real_mode_segment(self) -> None:
        try:
            output, segment_varnode, offset_varnode = get_x86_segment_varnodes(self._current_op)
        except ValueError as ex:
            raise NotImplementedError(f"Invalid x86 real-mode segment userop: {ex}") from ex

        self._convert_x86_segment_address(
            output,
            segment_varnode,
            offset_varnode,
            segment_shift=4,
            address_mask=X86_REAL_MODE_ADDRESS_MASK,
        )

    def _convert_x86_protected_mode_segment(self) -> None:
        try:
            output, segment_varnode, offset_varnode = get_x86_segment_varnodes(self._current_op)
        except ValueError as ex:
            raise NotImplementedError(f"Invalid x86 protected-mode segment userop: {ex}") from ex

        segment_bits = segment_varnode.size * 8
        offset_bits = offset_varnode.size * 8
        address_kind = (
            "x86-protected-16:16"
            if segment_bits == 16 and offset_bits == 16
            else f"x86-protected-{segment_bits}:{offset_bits}"
        )
        segment_register = None
        segment_register_origin = None
        if segment_varnode.space.name == "register":
            register_name = segment_varnode.getRegisterName()
            segment_register = register_name.lower() if register_name else None
            segment_register_origin = self._register_origin(segment_varnode)
        segment_tags = {"segment_register": segment_register} if segment_register else {}
        if segment_register_origin is not None and segment_register_origin != segment_register:
            segment_tags["segment_register_origin"] = segment_register_origin
        self._segmented_addresses[self._varnode_key(output)] = SegmentedAddress(
            self._manager.next_atom(),
            self._get_value(segment_varnode),
            self._get_value(offset_varnode),
            address_kind,
            bits=output.size * 8,
            ins_addr=self._manager.ins_addr,
            vex_block_addr=self._manager.block_addr,
            vex_stmt_idx=self._statement_idx,
            **segment_tags,
        )

    def _convert_x86_segment_address(
        self,
        output: Varnode,
        segment_varnode: Varnode,
        offset_varnode: Varnode,
        *,
        segment_shift: int,
        address_mask: int | None = None,
    ) -> None:
        output_bits = output.size * 8
        tags = {
            "ins_addr": self._manager.ins_addr,
            "vex_block_addr": self._manager.block_addr,
            "vex_stmt_idx": self._statement_idx,
        }
        segment = Convert(
            self._manager.next_atom(),
            segment_varnode.size * 8,
            output_bits,
            False,
            self._get_value(segment_varnode),
            **tags,
        )
        offset = Convert(
            self._manager.next_atom(),
            offset_varnode.size * 8,
            output_bits,
            False,
            self._get_value(offset_varnode),
            **tags,
        )
        shifted_segment = BinaryOp(
            self._manager.next_atom(),
            "Shl",
            [segment, Const(self._manager.next_atom(), segment_shift, output_bits)],
            signed=False,
            bits=output_bits,
            **tags,
        )
        linear_address = BinaryOp(
            self._manager.next_atom(),
            "Add",
            [shifted_segment, offset],
            signed=False,
            bits=output_bits,
            **tags,
        )
        address = linear_address
        if address_mask is not None:
            address = BinaryOp(
                self._manager.next_atom(),
                "And",
                [linear_address, Const(self._manager.next_atom(), address_mask, output_bits)],
                signed=False,
                bits=output_bits,
                **tags,
            )
        self._statements.append(self._set_value(output, address))

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

import logging
from typing import Union

import pypcode
from pypcode import OpCode, VarnodeData, PcodeOpRaw
import claripy
from claripy.ast.bv import BV

from ..engine import SimEngineBase
from ...utils.constants import DEFAULT_STATEMENT
from .lifter import IRSB, PcodeInstruction
from .behavior import OpBehavior

l = logging.getLogger(__name__)

class PcodeEmulatorMixin(SimEngineBase):
    """
    Mixin for P-Code execution.
    """

    _current_ins:      Union[PcodeInstruction, None]
    _current_op:       Union[PcodeOpRaw, None]
    _current_behavior: Union[OpBehavior, None]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._current_ins = None
        self._current_op = None
        self._current_behavior = None
        self._special_op_handlers = {
            OpCode.CPUI_LOAD:       self._execute_load,
            OpCode.CPUI_STORE:      self._execute_store,
            OpCode.CPUI_BRANCH:     self._execute_branch,
            OpCode.CPUI_CBRANCH:    self._execute_cbranch,
            OpCode.CPUI_BRANCHIND:  self._execute_branchind,
            OpCode.CPUI_CALL:       self._execute_call,
            OpCode.CPUI_CALLIND:    self._execute_callind,
            OpCode.CPUI_CALLOTHER:  self._execute_callother,
            OpCode.CPUI_RETURN:     self._execute_ret,
            OpCode.CPUI_MULTIEQUAL: self._execute_multiequal,
            OpCode.CPUI_INDIRECT:   self._execute_indirect,
            OpCode.CPUI_SEGMENTOP:  self._execute_segment_op,
            OpCode.CPUI_CPOOLREF:   self._execute_cpool_ref,
            OpCode.CPUI_NEW:        self._execute_new,
        }

    def handle_pcode_block(self, irsb: IRSB) -> None:
        """
        Execute a single IRSB.

        :param irsb: The block to be executed.
        """
        self.irsb = irsb
        # Hack on a handler here to track whether exit has been handled or not
        # FIXME: Vex models this as a known exit statement, which we should also
        # do here. For now, handle it this way.
        self.state.scratch.exit_handled = False

        fallthru_addr = None
        for i, ins in enumerate(irsb._instructions):
            l.debug("Executing machine instruction @ %#x (%d of %d)", ins.addr.getOffset(), i+1, len(irsb._instructions))

            # Execute a single instruction of the emulated machine
            self._current_ins = ins
            self.state.scratch.ins_addr = self._current_ins.addr.getOffset()

            # FIXME: Hacking this on here but ideally should use "scratch".
            self._pcode_tmps = {}  # FIXME: Consider alignment requirements

            for op in self._current_ins.ops:
                self._current_op = op
                self._current_behavior = irsb.behaviors.get_behavior_for_opcode(self._current_op.getOpcode())
                l.debug("Executing p-code op: %s", self._current_ins.pp_op_str(self._current_op))
                self._execute_current_op()

            self._current_op = None
            self._current_behavior = None
            fallthru_addr = ins.addr.getOffset() + ins.length

        if not self.state.scratch.exit_handled:
            self.successors.add_successor(
                self.state,
                fallthru_addr,
                self.state.scratch.guard,
                "Ijk_Boring",
                exit_stmt_idx=DEFAULT_STATEMENT,
                exit_ins_addr=self.state.scratch.ins_addr,
            )

    def _execute_current_op(self) -> None:
        """
        Execute the current p-code operation.
        """
        assert self._current_behavior is not None

        if self._current_behavior.is_special:
            self._special_op_handlers[self._current_behavior.opcode]()
        elif self._current_behavior.is_unary:
            self._execute_unary()
        else:
            self._execute_binary()

    def _map_register_name(self, var_data: VarnodeData) -> int:
        """
        Map SLEIGH register offset to ArchInfo register offset based on name.

        :param var_data: The varnode to translate.
        :return:         The register file offset.
        """
        # FIXME: Will need performance optimization
        # FIXME: Should not get trans object this way. Moreover, should have a faster mapping method than going through trans
        trans = self.irsb._instructions[0].trans
        reg_name = trans.getRegisterName(var_data.space, var_data.offset, var_data.size)
        try:
            reg_offset = self.state.project.arch.get_register_offset(reg_name.lower())
            l.debug("Mapped register '%s' to offset %x", reg_name, reg_offset)
        except ValueError:
            reg_offset = var_data.offset + 0x100000
            l.debug("Could not map register '%s' from archinfo. Mapping to %x", reg_name, reg_offset)
        return reg_offset

    @staticmethod
    def _adjust_value_size(num_bits: int, v_in: BV) -> BV:
        """
        Ensure given bv is num_bits bits long by either zero extending or truncating.
        """
        if v_in.size() > num_bits:
            v_out = v_in[num_bits-1:0]
            l.debug('Truncating value %s (%d bits) to %s (%d bits)',
                    v_in,
                    v_in.size(),
                    v_out,
                    num_bits)
            return v_out
        elif v_in.size() < num_bits:
            v_out = v_in.zero_extend(num_bits-v_in.size())
            l.debug('Extending value %s (%d bits) to %s (%d bits)',
                    v_in,
                    v_in.size(),
                    v_out,
                    num_bits)
            return v_out
        else:
            return v_in

    def _set_value(self, var_data: VarnodeData, value: BV) -> None:
        """
        Store a value for a given varnode.

        This method stores to the appropriate register, or unique space,
        depending on the space indicated by the varnode.

        :param var_data: The varnode to store into.
        :param value:    The value to store.
        """
        space_name = var_data.space.getName()

        # FIXME: Consider moving into behavior.py
        value = self._adjust_value_size(var_data.size*8, value)
        assert var_data.size*8 == value.size()

        l.debug("Storing %s %x %s %d", space_name, var_data.offset, value, var_data.size)
        if space_name == "register":
            self.state.registers.store(
                self._map_register_name(var_data), value, size=var_data.size
            )

        elif space_name == "unique":
            self._pcode_tmps[var_data.offset] = value

        elif space_name in ("ram", "mem"):
            l.debug("Storing %s to offset %s", value, var_data.offset)
            self.state.memory.store(var_data.offset, value, endness=self.project.arch.memory_endness)

        else:
            raise NotImplementedError()

    def _get_value(self, var_data: VarnodeData) -> BV:
        """
        Get a value for a given varnode.

        This method loads from the appropriate const, register, unique, or RAM
        space, depending on the space indicated by the varnode.

        :param var_data: The varnode to load from.
        :return:         The value loaded.
        """
        space_name = var_data.space.getName()
        size = var_data.size
        l.debug("Loading %s - %x x %d", space_name, var_data.offset, size)
        if space_name == "const":
            return claripy.BVV(var_data.offset, size*8)
        elif space_name == "register":
            return self.state.registers.load(self._map_register_name(var_data), size=size)
        elif space_name == "unique":
            # FIXME: Support loading data of different sizes. For now, assume
            # size of values read are same as size written.
            assert self._pcode_tmps[var_data.offset].size() == size*8
            return self._pcode_tmps[var_data.offset]
        elif space_name in ("ram", "mem"):
            val = self.state.memory.load(var_data.offset, endness=self.project.arch.memory_endness, size=size)
            l.debug("Loaded %s from offset %s", val, var_data.offset)
            return val
        else:
            raise NotImplementedError()

    def _execute_unary(self) -> None:
        """
        Execute the unary behavior of the current op.
        """
        in1 = self._get_value(self._current_op.getInput(0))
        l.debug("in1 = %s", in1)
        out = self._current_behavior.evaluate_unary(
            self._current_op.getOutput().size, self._current_op.getInput(0).size, in1
        )
        l.debug("out unary = %s", out)
        self._set_value(self._current_op.getOutput(), out)

    def _execute_binary(self) -> None:
        """
        Execute the binary behavior of the current op.
        """
        in1 = self._get_value(self._current_op.getInput(0))
        in2 = self._get_value(self._current_op.getInput(1))
        l.debug("in1 = %s", in1)
        l.debug("in2 = %s", in2)
        out = self._current_behavior.evaluate_binary(
            self._current_op.getOutput().size, self._current_op.getInput(0).size, in1, in2
        )
        l.debug("out binary = %s", out)
        self._set_value(self._current_op.getOutput(), out)

    def _execute_load(self) -> None:
        """
        Execute a p-code load operation.
        """
        spc = pypcode.Address.getSpaceFromConst(self._current_op.getInput(0).getAddr())
        assert spc.getName() in ("ram", "mem")
        off = self._get_value(self._current_op.getInput(1))
        out = self._current_op.getOutput()
        res = self.state.memory.load(off, out.size, endness=self.project.arch.memory_endness)
        l.debug("Loaded %s from offset %s", res, off)
        self._set_value(out, res)

    def _execute_store(self) -> None:
        """
        Execute a p-code store operation.
        """
        spc = pypcode.Address.getSpaceFromConst(self._current_op.getInput(0).getAddr())
        assert spc.getName() in ("ram", "mem")
        off = self._get_value(self._current_op.getInput(1))
        data = self._get_value(self._current_op.getInput(2))
        l.debug("Storing %s at offset %s", data, off)
        self.state.memory.store(off, data, endness=self.project.arch.memory_endness)

    def _execute_branch(self) -> None:
        """
        Execute a p-code branch operation.
        """
        dest_addr = self._current_op.getInput(0).getAddr()
        if dest_addr.isConstant():
            raise NotImplementedError("P-code relative branch not supported yet")

        self.state.scratch.exit_handled = True
        expr = dest_addr.getOffset()
        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            "Ijk_Boring",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

    def _execute_cbranch(self) -> None:
        """
        Execute a p-code conditional branch operation.
        """
        cond = self._get_value(self._current_op.getInput(1))
        dest_addr = self._current_op.getInput(0).getAddr()
        if dest_addr.isConstant():
            raise NotImplementedError("P-code relative branch not supported yet")

        exit_state = self.state.copy()
        self.successors.add_successor(
            exit_state,
            dest_addr.getOffset(),
            cond != 0,
            "Ijk_Boring",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

        cont_state = self.state
        cont_condition = cond == 0
        cont_state.add_constraints(cont_condition)
        cont_state.scratch.guard = claripy.And(
            cont_state.scratch.guard, cont_condition
        )

    def _execute_ret(self) -> None:
        """
        Execute a p-code return operation.
        """
        self.state.scratch.exit_handled = True
        self.successors.add_successor(
            self.state,
            self.state.regs.ip,
            self.state.scratch.guard,
            "Ijk_Ret",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

    def _execute_branchind(self) -> None:
        """
        Execute a p-code indirect branch operation.
        """
        self.state.scratch.exit_handled = True
        expr = self._get_value(self._current_op.getInput(0))
        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            "Ijk_Boring",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

    def _execute_call(self) -> None:
        """
        Execute a p-code call operation.
        """
        self.state.scratch.exit_handled = True
        expr = self._current_op.getInput(0).getAddr().getOffset()
        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            "Ijk_Call",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

    def _execute_callind(self) -> None:
        """
        Execute a p-code indirect call operation.
        """
        self.state.scratch.exit_handled = True
        expr = self._get_value(self._current_op.getInput(0))
        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            "Ijk_Call",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

    def _execute_callother(self) -> None:
        raise NotImplementedError("CALLOTHER emulation not currently supported")

    def _execute_multiequal(self) -> None:
        raise NotImplementedError("MULTIEQUAL appearing in unheritaged code?")

    def _execute_indirect(self) -> None:
        raise NotImplementedError("INDIRECT appearing in unheritaged code?")

    def _execute_segment_op(self) -> None:
        raise NotImplementedError("SEGMENTOP emulation not currently supported")

    def _execute_cpool_ref(self) -> None:
        raise NotImplementedError("Cannot currently emulate cpool operator")

    def _execute_new(self) -> None:
        raise NotImplementedError("Cannot currently emulate new operator")

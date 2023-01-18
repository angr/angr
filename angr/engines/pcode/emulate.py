import logging
from typing import Union

from pypcode import OpCode, Varnode, PcodeOp, Translation
import claripy
from claripy.ast.bv import BV

from ..engine import SimEngineBase
from ...utils.constants import DEFAULT_STATEMENT
from .lifter import IRSB
from .behavior import OpBehavior
from ...errors import AngrError
from ...state_plugins.inspect import BP_BEFORE, BP_AFTER


l = logging.getLogger(__name__)


class PcodeEmulatorMixin(SimEngineBase):
    """
    Mixin for p-code execution.
    """

    _current_ins: Union[Translation, None]
    _current_op: Union[PcodeOp, None]
    _current_behavior: Union[OpBehavior, None]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._current_ins = None
        self._current_op = None
        self._current_behavior = None
        self._special_op_handlers = {
            OpCode.LOAD: self._execute_load,
            OpCode.STORE: self._execute_store,
            OpCode.BRANCH: self._execute_branch,
            OpCode.CBRANCH: self._execute_cbranch,
            OpCode.BRANCHIND: self._execute_branchind,
            OpCode.CALL: self._execute_call,
            OpCode.CALLIND: self._execute_callind,
            OpCode.CALLOTHER: self._execute_callother,
            OpCode.RETURN: self._execute_ret,
            OpCode.MULTIEQUAL: self._execute_multiequal,
            OpCode.INDIRECT: self._execute_indirect,
            OpCode.SEGMENTOP: self._execute_segment_op,
            OpCode.CPOOLREF: self._execute_cpool_ref,
            OpCode.NEW: self._execute_new,
        }

    def handle_pcode_block(self, irsb: IRSB) -> None:
        """
        Execute a single IRSB.

        :param irsb: Block to be executed.
        """
        self.irsb = irsb
        # Hack on a handler here to track whether exit has been handled or not
        # FIXME: Vex models this as a known exit statement, which we should also
        # do here. For now, handle it this way.
        self.state.scratch.exit_handled = False

        fallthru_addr = None
        for i, ins in enumerate(irsb._instructions):
            l.debug(
                "Executing machine instruction @ %#x (%d of %d)", ins.address.offset, i + 1, len(irsb._instructions)
            )

            # Execute a single instruction of the emulated machine
            self._current_ins = ins
            self.state.scratch.ins_addr = self._current_ins.address.offset

            # FIXME: Hacking this on here but ideally should use "scratch".
            self._pcode_tmps = {}  # FIXME: Consider alignment requirements

            self.state._inspect("instruction", BP_BEFORE, instruction=self._current_ins.address.offset)
            offset = self.state.scratch.statement_offset
            self.state.scratch.statement_offset = 0
            for op in self._current_ins.ops[offset:]:
                self._current_op = op
                self._current_behavior = irsb.behaviors.get_behavior_for_opcode(self._current_op.opcode)
                l.debug("Executing p-code op: %s", self._current_op)
                self._execute_current_op()
            self.state._inspect("instruction", BP_AFTER)

            self._current_op = None
            self._current_behavior = None
            fallthru_addr = ins.address.offset + ins.length

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

    def _map_register_name(self, varnode: Varnode) -> int:
        """
        Map SLEIGH register offset to ArchInfo register offset based on name.

        :param varnode: Varnode to translate.
        :return:        Register file offset.
        """
        # FIXME: Will need performance optimization
        # FIXME: Should not get trans object this way. There should be a faster mapping method than going through trans
        reg_name = varnode.get_register_name()
        try:
            reg_offset = self.state.project.arch.get_register_offset(reg_name.lower())
            l.debug("Mapped register '%s' to offset %x", reg_name, reg_offset)
        except ValueError:
            reg_offset = varnode.offset + 0x100000
            l.debug("Could not map register '%s' from archinfo. Mapping to %x", reg_name, reg_offset)
        return reg_offset

    @staticmethod
    def _adjust_value_size(num_bits: int, v_in: BV) -> BV:
        """
        Ensure given bv is num_bits bits long by either zero extending or truncating.
        """
        if v_in.size() > num_bits:
            v_out = v_in[num_bits - 1 : 0]
            l.debug("Truncating value %s (%d bits) to %s (%d bits)", v_in, v_in.size(), v_out, num_bits)
            return v_out
        elif v_in.size() < num_bits:
            v_out = v_in.zero_extend(num_bits - v_in.size())
            l.debug("Extending value %s (%d bits) to %s (%d bits)", v_in, v_in.size(), v_out, num_bits)
            return v_out
        else:
            return v_in

    def _set_value(self, varnode: Varnode, value: BV) -> None:
        """
        Store a value for a given varnode.

        This method stores to the appropriate register, or unique space,
        depending on the space indicated by the varnode.

        :param varnode: Varnode to store into.
        :param value:   Value to store.
        """
        space_name = varnode.space.name

        # FIXME: Consider moving into behavior.py
        value = self._adjust_value_size(varnode.size * 8, value)
        assert varnode.size * 8 == value.size()

        l.debug("Storing %s %x %s %d", space_name, varnode.offset, value, varnode.size)
        if space_name == "register":
            self.state.registers.store(
                self._map_register_name(varnode), value, size=varnode.size, endness=self.project.arch.register_endness
            )

        elif space_name == "unique":
            self._pcode_tmps[varnode.offset] = value

        elif space_name in ("ram", "mem"):
            l.debug("Storing %s to offset %s", value, varnode.offset)
            self.state.memory.store(varnode.offset, value, endness=self.project.arch.memory_endness)

        else:
            raise AngrError(f"Attempted write to unhandled address space '{space_name}'")

    def _get_value(self, varnode: Varnode) -> BV:
        """
        Get a value for a given varnode.

        This method loads from the appropriate const, register, unique, or RAM
        space, depending on the space indicated by the varnode.

        :param varnode: Varnode to load from.
        :return:        Value loaded.
        """
        space_name = varnode.space.name
        size = varnode.size
        l.debug("Loading %s - %x x %d", space_name, varnode.offset, size)
        if space_name == "const":
            return claripy.BVV(varnode.offset, size * 8)
        elif space_name == "register":
            return self.state.registers.load(
                self._map_register_name(varnode), size=size, endness=self.project.arch.register_endness
            )

        elif space_name == "unique":
            # FIXME: Support loading data of different sizes. For now, assume
            # size of values read are same as size written.
            try:
                assert self._pcode_tmps[varnode.offset].size() == size * 8
            except KeyError:
                # FIXME: Add unique space to state tracking?
                l.warning("Uninitialized read from unique space offset %x", varnode.offset)
                self._pcode_tmps[varnode.offset] = claripy.BVV(0, size * 8)
            return self._pcode_tmps[varnode.offset]

        elif space_name in ("ram", "mem"):
            val = self.state.memory.load(varnode.offset, endness=self.project.arch.memory_endness, size=size)
            l.debug("Loaded %s from offset %s", val, varnode.offset)
            return val

        else:
            raise AngrError(f"Attempted read from unhandled address space '{space_name}'")

    def _execute_unary(self) -> None:
        """
        Execute the unary behavior of the current op.
        """
        in1 = self._get_value(self._current_op.inputs[0])
        l.debug("in1 = %s", in1)
        out = self._current_behavior.evaluate_unary(self._current_op.output.size, self._current_op.inputs[0].size, in1)
        l.debug("out unary = %s", out)
        self._set_value(self._current_op.output, out)

    def _execute_binary(self) -> None:
        """
        Execute the binary behavior of the current op.
        """
        in1 = self._get_value(self._current_op.inputs[0])
        in2 = self._get_value(self._current_op.inputs[1])
        l.debug("in1 = %s", in1)
        l.debug("in2 = %s", in2)
        out = self._current_behavior.evaluate_binary(
            self._current_op.output.size, self._current_op.inputs[0].size, in1, in2
        )
        l.debug("out binary = %s", out)
        self._set_value(self._current_op.output, out)

    def _execute_load(self) -> None:
        """
        Execute a p-code load operation.
        """
        spc = self._current_op.inputs[0].get_space_from_const()
        off = self._get_value(self._current_op.inputs[1])
        out = self._current_op.output
        if spc.name in ("ram", "mem"):
            res = self.state.memory.load(off, out.size, endness=self.project.arch.memory_endness)
        elif spc.name in "register":
            res = self.state.registers.load(off, size=out.size, endness=self.project.arch.register_endness)
        else:
            raise AngrError("Load from unhandled address space")
        l.debug("Loaded %s from offset %s", res, off)
        self._set_value(out, res)

    def _execute_store(self) -> None:
        """
        Execute a p-code store operation.
        """
        spc = self._current_op.inputs[0].get_space_from_const()
        off = self._get_value(self._current_op.inputs[1])
        data = self._get_value(self._current_op.inputs[2])
        l.debug("Storing %s at offset %s", data, off)
        if spc.name in ("ram", "mem"):
            self.state.memory.store(off, data, endness=self.project.arch.memory_endness)
        elif spc.name == "register":
            self.state.registers.store(off, data, endness=self.project.arch.register_endness)
        else:
            raise AngrError("Store to unhandled address space")

    def _execute_branch(self) -> None:
        """
        Execute a p-code branch operation.
        """
        dest_addr = self._current_op.inputs[0].get_addr()
        if dest_addr.is_constant:
            expr = self.state.scratch.ins_addr
            self.state.scratch.statement_offset = dest_addr.offset + self._current_op.seq.uniq
        else:
            expr = dest_addr.offset

        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            "Ijk_Boring",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

        self.state.scratch.exit_handled = True

    def _execute_cbranch(self) -> None:
        """
        Execute a p-code conditional branch operation.
        """
        exit_state = self.state.copy()
        cond = self._get_value(self._current_op.inputs[1])
        dest_addr = self._current_op.inputs[0].get_addr()

        if dest_addr.is_constant:
            expr = exit_state.scratch.ins_addr
            exit_state.scratch.statement_offset = dest_addr.offset + self._current_op.seq.uniq
        else:
            expr = dest_addr.offset

        self.successors.add_successor(
            exit_state,
            expr,
            cond != 0,
            "Ijk_Boring",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

        cont_state = self.state
        cont_condition = cond == 0
        cont_state.add_constraints(cont_condition)
        cont_state.scratch.guard = claripy.And(cont_state.scratch.guard, cont_condition)

    def _execute_ret(self) -> None:
        """
        Execute a p-code return operation.
        """
        ret_addr = self._get_value(self._current_op.inputs[0])

        self.successors.add_successor(
            self.state,
            ret_addr,
            self.state.scratch.guard,
            "Ijk_Ret",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

        self.state.scratch.exit_handled = True

    def _execute_branchind(self) -> None:
        """
        Execute a p-code indirect branch operation.
        """
        expr = self._get_value(self._current_op.inputs[0])

        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            "Ijk_Boring",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

        self.state.scratch.exit_handled = True

    def _execute_call(self) -> None:
        """
        Execute a p-code call operation.
        """
        expr = self._current_op.inputs[0].get_addr().offset

        self.successors.add_successor(
            self.state.copy(),  # FIXME: Check extra processing after call
            expr,
            self.state.scratch.guard,
            "Ijk_Call",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

        self.state.scratch.exit_handled = True

    def _execute_callind(self) -> None:
        """
        Execute a p-code indirect call operation.
        """
        expr = self._get_value(self._current_op.inputs[0])

        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            "Ijk_Call",
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )

        self.state.scratch.exit_handled = True

    def _execute_callother(self) -> None:  # pylint:disable=no-self-use
        raise AngrError("CALLOTHER emulation not currently supported")

    def _execute_multiequal(self) -> None:  # pylint:disable=no-self-use
        raise AngrError("MULTIEQUAL appearing in unheritaged code?")

    def _execute_indirect(self) -> None:  # pylint:disable=no-self-use
        raise AngrError("INDIRECT appearing in unheritaged code?")

    def _execute_segment_op(self) -> None:  # pylint:disable=no-self-use
        raise AngrError("SEGMENTOP emulation not currently supported")

    def _execute_cpool_ref(self) -> None:  # pylint:disable=no-self-use
        raise AngrError("Cannot currently emulate cpool operator")

    def _execute_new(self) -> None:  # pylint:disable=no-self-use
        raise AngrError("Cannot currently emulate new operator")

from __future__ import annotations
import logging

import claripy
from claripy.ast.bv import BV

from ..engine import SimEngineBase
from ...utils.constants import DEFAULT_STATEMENT
from .lifter import IRSB
from .behavior import OpBehavior
from ...errors import AngrError
from ...state_plugins.inspect import BP_BEFORE, BP_AFTER
import contextlib

with contextlib.suppress(ImportError):
    from pypcode import OpCode, Varnode, PcodeOp


l = logging.getLogger(__name__)


class PcodeEmulatorMixin(SimEngineBase):
    """
    Mixin for p-code execution.
    """

    _current_op: PcodeOp | None
    _current_op_idx: int
    _current_behavior: OpBehavior | None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._current_op = None
        self._current_behavior = None

    def handle_pcode_block(self, irsb: IRSB) -> None:
        """
        Execute a single P-Code IRSB.

        :param irsb: Block to be executed.
        """
        self.irsb = irsb

        # Hack on a handler here to track whether exit has been handled or not
        # FIXME: Vex models this as a known exit statement, which we should also
        # do here. For now, handle it this way.
        self.state.scratch.exit_handled = False
        self._pcode_tmps = {}

        fallthru_addr = self.irsb.addr
        self.state.scratch.ins_addr = self.irsb.addr
        last_imark_op_idx = 0

        # Note: start_op_idx is instruction relative
        start_op_idx = self.state.scratch.statement_offset
        self.state.scratch.statement_offset = 0
        assert start_op_idx == 0, "FIXME: Test statement_offset behavior"

        for op_idx, op in enumerate(irsb._ops[start_op_idx:]):  # FIXME: Shouldn't use protected members of IRSB
            op_idx += start_op_idx

            if op.opcode == OpCode.IMARK:
                if op_idx > 0:
                    # Trigger BP for previous instruction once we reach next IMARK
                    self.state._inspect("instruction", BP_AFTER)

                decode_addr = op.inputs[0].offset
                last_imark_op_idx = op_idx

                # Note: instruction BP will not be triggered on p-code-relative jumps
                l.debug("Executing machine instruction @ %#x", decode_addr)
                for vn in op.inputs:
                    self.state._inspect("instruction", BP_BEFORE, instruction=vn.offset)

                # FIXME: Hacking this on here but ideally should use "scratch".
                self._pcode_tmps = {}  # FIXME: Consider alignment requirements
                self.state.scratch.ins_addr = decode_addr
                fallthru_addr = op.inputs[-1].offset + op.inputs[-1].size
                continue

            self._current_op = op
            self._current_op_idx = op_idx - last_imark_op_idx
            l.debug("Executing P-Code op: %s", self._current_op)
            self._execute_current_op()
            self._current_op = None

        if self.state.scratch.statement_offset == 0:
            self.state._inspect("instruction", BP_AFTER)

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
        self._current_behavior = self.irsb.behaviors.get_behavior_for_opcode(self._current_op.opcode)

        if self._current_behavior.is_special:
            handlers = {
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
            handlers[self._current_behavior.opcode]()
        elif self._current_behavior.is_unary:
            self._execute_unary()
        else:
            self._execute_binary()

        self._current_behavior = None

    def _map_register_name(self, varnode: Varnode) -> int:
        """
        Map SLEIGH register offset to ArchInfo register offset based on name.

        :param varnode: Varnode to translate.
        :return:        Register file offset.
        """
        # FIXME: Will need performance optimization
        # FIXME: Should not get trans object this way. There should be a faster mapping method than going through trans
        reg_name = varnode.getRegisterName()
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
        if v_in.size() < num_bits:
            v_out = v_in.zero_extend(num_bits - v_in.size())
            l.debug("Extending value %s (%d bits) to %s (%d bits)", v_in, v_in.size(), v_out, num_bits)
            return v_out
        return v_in

    def _set_value(self, varnode: Varnode, value: BV) -> None:
        """
        Store a value for a given varnode.

        This method stores to the appropriate register, or unique space,
        depending on the space indicated by the varnode.

        :param varnode: Varnode to store into.
        :param value:   Value to store.
        """
        # FIXME: Consider moving into behavior.py
        value = self._adjust_value_size(varnode.size * 8, value)
        assert varnode.size * 8 == value.size()

        space = varnode.space
        l.debug("Storing %s %x %s %d", space.name, varnode.offset, value, varnode.size)
        if space.name == "register":
            self.state.registers.store(
                self._map_register_name(varnode), value, size=varnode.size, endness=self.project.arch.register_endness
            )

        elif space.name == "unique":
            self._pcode_tmps[varnode.offset] = value

        elif space.name.lower() in ("ram", "mem"):
            l.debug("Storing %s to offset %s", value, varnode.offset)
            self.state.memory.store(varnode.offset, value, endness=self.project.arch.memory_endness)

        else:
            raise AngrError(f"Attempted write to unhandled address space '{space.name}'")

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
        if space_name == "register":
            return self.state.registers.load(
                self._map_register_name(varnode), size=size, endness=self.project.arch.register_endness
            )

        if space_name == "unique":
            # FIXME: Support loading data of different sizes. For now, assume
            # size of values read are same as size written.
            try:
                assert self._pcode_tmps[varnode.offset].size() == size * 8
            except KeyError:
                # FIXME: Add unique space to state tracking?
                l.warning("Uninitialized read from unique space offset %x", varnode.offset)
                self._pcode_tmps[varnode.offset] = claripy.BVV(0, size * 8)
            return self._pcode_tmps[varnode.offset]

        if space_name.lower() in ("ram", "mem"):
            val = self.state.memory.load(varnode.offset, endness=self.project.arch.memory_endness, size=size)
            l.debug("Loaded %s from offset %s", val, varnode.offset)
            return val

        raise AngrError(f"Attempted read from unhandled address space '{space_name}'")

    def _execute_unary(self) -> None:
        """
        Execute the unary behavior of the current op.
        """
        in0 = self._get_value(self._current_op.inputs[0])
        out = self._current_behavior.evaluate_unary(self._current_op.output.size, self._current_op.inputs[0].size, in0)
        self._set_value(self._current_op.output, out)

    def _execute_binary(self) -> None:
        """
        Execute the binary behavior of the current op.
        """

        # Validate output
        assert self._current_op.output is not None
        if (
            self._current_op.opcode
            in [
                OpCode.INT_LESS,
                OpCode.INT_SLESS,
                OpCode.INT_LESSEQUAL,
                OpCode.INT_SLESSEQUAL,
                OpCode.INT_EQUAL,
                OpCode.INT_NOTEQUAL,
            ]
            and self._current_op.output.size != 1
        ):
            l.warning(
                "SLEIGH spec states output size for op %s must be 1, but op has %d",
                self._current_op.opcode.__name__,
                self._current_op.output.size,
            )

        # Validate ops that mandate inputs of equal sizes
        # Validate ops that mandate output of greater size

        # Validate inputs

        in0 = self._get_value(self._current_op.inputs[0])
        in1 = self._get_value(self._current_op.inputs[1])
        out = self._current_behavior.evaluate_binary(
            self._current_op.output.size, self._current_op.inputs[0].size, in0, in1
        )
        self._set_value(self._current_op.output, out)

    def _execute_load(self) -> None:
        """
        Execute a p-code load operation.
        """
        space = self._current_op.inputs[0].getSpaceFromConst()
        offset = self._get_value(self._current_op.inputs[1])
        out = self._current_op.output
        if space.name.lower() in ("ram", "mem"):
            res = self.state.memory.load(offset, out.size, endness=self.project.arch.memory_endness)
        elif space.name in "register":
            res = self.state.registers.load(offset, size=out.size, endness=self.project.arch.register_endness)
        else:
            raise AngrError("Load from unhandled address space")
        l.debug("Loaded %s from offset %s", res, offset)
        self._set_value(out, res)

        # CHECKME: wordsize condition in cpuid load

    def _execute_store(self) -> None:
        """
        Execute a p-code store operation.
        """
        space = self._current_op.inputs[0].getSpaceFromConst()
        offset = self._get_value(self._current_op.inputs[1])
        data = self._get_value(self._current_op.inputs[2])
        l.debug("Storing %s at offset %s", data, offset)
        if space.name.lower() in ("ram", "mem"):
            self.state.memory.store(offset, data, endness=self.project.arch.memory_endness)
        elif space.name == "register":
            self.state.registers.store(offset, data, endness=self.project.arch.register_endness)
        else:
            raise AngrError("Store to unhandled address space")

    def _execute_branch(self) -> None:
        """
        Execute a p-code branch operation.
        """
        dest = self._current_op.inputs[0]
        if dest.space.name == "const":
            # P-Code-relative branch
            expr = self.state.scratch.ins_addr
            self.state.scratch.statement_offset = self._current_op_idx + dest.offset
        else:
            expr = dest.offset

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
        dest = self._current_op.inputs[0]

        if dest.space.name == "const":
            # P-Code-relative branch
            expr = exit_state.scratch.ins_addr
            exit_state.scratch.statement_offset = self._current_op_idx + dest.offset
        else:
            expr = dest.offset

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
        self.successors.add_successor(
            self.state,
            self._get_value(self._current_op.inputs[0]),
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
        self.successors.add_successor(
            self.state,
            self._get_value(self._current_op.inputs[0]),
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

        # FIXME: Spec claims CALL is semantically equivalent to BRANCH. But are p-code relative calls allowed? We assume
        #        not.

        self.successors.add_successor(
            self.state.copy(),  # FIXME: Check extra processing after call
            self._current_op.inputs[0].offset,
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
        self.successors.add_successor(
            self.state,
            self._get_value(self._current_op.inputs[0]),
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

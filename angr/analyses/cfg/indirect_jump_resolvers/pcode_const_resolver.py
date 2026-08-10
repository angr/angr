from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import claripy
import pypcode

from angr.engines.pcode.behavior import BehaviorFactory
from angr.engines.pcode.lifter import IRSB as PcodeIRSB
from angr.errors import AngrError

from .propagator_utils import PropagatorLoadCallback
from .resolver import IndirectJumpResolver

if TYPE_CHECKING:
    from claripy.ast.bv import BV
    from pypcode import PcodeOp, Varnode

_l = logging.getLogger(name=__name__)


# Address spaces naming a location in the loaded image rather than a machine register or a lifter temporary.
MEMORY_SPACES = frozenset({"ram", "mem"})

# Sizes that Clemory.unpack_word can read.
LOADABLE_SIZES = frozenset({1, 2, 4, 8})

# Varnode identity: address space name, offset within the space, and size in bytes.
VarnodeKey = tuple[str, int, int]


class PcodeConstantResolver(IndirectJumpResolver):
    """
    Resolve an indirect jump or call lifted by the p-code lifter by constant-folding the operations of the block that
    ends in BRANCHIND or CALLIND.

    The generic resolvers cannot do this. They read the default exit out of ``IRSB.next`` and pattern-match VEX
    statements, while a p-code IRSB has no statements and leaves ``next`` unset whenever its default exit is indirect,
    keeping the target only in the operands of the terminating operation.

    Folding covers a single block, which is enough for the literal pool idiom that several p-code architectures reach
    most of their calls through::

        400468  mov.l   0x400480, r1      ; r1 <- the constant stored at 0x400480
        40046a  jsr     @r1
        40046c  nop                       ; delay slot

    A target that depends on a value defined outside the block is left unresolved.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)
        self._behaviors = BehaviorFactory()
        self._load_callback = PropagatorLoadCallback(project).propagator_load_callback

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        # The p-code lifter leaves next unset exactly when the default exit is BRANCHIND, CALLIND, or RETURN.
        return isinstance(block, PcodeIRSB) and block.next is None and jumpkind in {"Ijk_Boring", "Ijk_Call"}

    def resolve(  # pylint:disable=unused-argument
        self,
        cfg,
        addr: int,
        func_addr: int,
        block: PcodeIRSB,
        jumpkind: str,
        func_graph_complete: bool = True,
        **kwargs,
    ):
        """
        :param cfg:         The CFG analysis object.
        :param addr:        Address of the indirect jump.
        :param func_addr:   Address of the function that this indirect jump belongs to.
        :param block:       The p-code IRSB of the indirect jump.
        :param jumpkind:    The jumpkind of the default exit.
        :return:            A tuple of a boolean indicating whether the resolution is successful or not, and a list of
                            resolved targets (ints).
        """
        target = self._fold_default_exit(block)
        if target is None or not self._is_target_valid(cfg, target):
            return False, []

        _l.debug("PcodeConstantResolver: resolved the indirect exit of block %#x to %#x.", addr, target)
        return True, [target]

    def _fold_default_exit(self, block: PcodeIRSB) -> int | None:
        """
        Interpret the operations of the block over concrete values and return the target of its terminating BRANCHIND
        or CALLIND.

        :param block:   The p-code IRSB of the indirect jump.
        :return:        The target address, or None if it does not fold to a constant.
        """
        values: dict[VarnodeKey, BV] = {}
        # Set once the block has written to memory. Nothing tracks where, so from that point on only memory that
        # cannot be written at all may still be read.
        memory_written = False

        for op in block.ops:
            opcode = op.opcode

            if opcode == pypcode.OpCode.IMARK:
                continue

            if opcode in {pypcode.OpCode.BRANCHIND, pypcode.OpCode.CALLIND}:
                target = self._read(values, op.inputs[0], memory_written)
                return None if target is None else target.concrete_value

            if opcode in {pypcode.OpCode.BRANCH, pypcode.OpCode.CBRANCH} and op.inputs[0].space.name == "const":
                # A p-code relative branch jumps within the operation list itself, so the operations after it are not
                # the ones that run next.
                return None

            if opcode == pypcode.OpCode.CALLOTHER:
                # A user-defined operation, with effects that are not modelled here.
                values.clear()
                memory_written = True
                continue

            if opcode == pypcode.OpCode.STORE:
                # Nothing tracks where a store lands, so every location in the space it targets becomes unknown.
                store_space = op.inputs[0].getSpaceFromConst().name
                for key in [k for k in values if k[0] == store_space]:
                    del values[key]
                memory_written = True
                continue

            if op.output is None:
                continue

            if op.output.space.name.lower() in MEMORY_SPACES:
                memory_written = True
                continue

            self._write(values, op.output, self._evaluate(values, op, memory_written))

        return None

    def _evaluate(self, values: dict[VarnodeKey, BV], op: PcodeOp, memory_written: bool) -> BV | None:
        """
        Compute the concrete output of a single p-code operation.

        :param values:          Concrete values of the varnodes defined so far in the block.
        :param op:              The operation to evaluate.
        :param memory_written:  Whether the block has written to memory before this operation.
        :return:                The output value, or None if it is not concrete or the operation is not modelled.
        """
        output = op.output
        if output is None:
            return None

        if op.opcode == pypcode.OpCode.LOAD:
            if op.inputs[0].getSpaceFromConst().name.lower() not in MEMORY_SPACES:
                return None
            addr = self._read(values, op.inputs[1], memory_written)
            return None if addr is None else self._load(addr.concrete_value, output.size, memory_written)

        behavior = self._behaviors.get_behavior_for_opcode(op.opcode)
        if behavior.is_special:
            return None

        inputs = []
        for varnode in op.inputs:
            value = self._read(values, varnode, memory_written)
            if value is None:
                return None
            inputs.append(value)

        try:
            if behavior.is_unary:
                value = behavior.evaluate_unary(output.size, op.inputs[0].size, inputs[0])
            else:
                value = behavior.evaluate_binary(output.size, op.inputs[0].size, inputs[0], inputs[1])
        except (AngrError, IndexError, claripy.ClaripyError):
            return None

        if not value.concrete:
            return None

        # Behaviors return the width their semantics imply, which is not always the width of the output varnode.
        # PcodeEmulatorMixin adjusts the same way before storing.
        bits = output.size * 8
        if value.size() > bits:
            return value[bits - 1 : 0]
        if value.size() < bits:
            return value.zero_extend(bits - value.size())
        return value

    def _read(self, values: dict[VarnodeKey, BV], varnode: Varnode, memory_written: bool) -> BV | None:
        """
        Read the concrete value of a varnode.

        :param values:          Concrete values of the varnodes defined so far in the block.
        :param varnode:         The varnode to read.
        :param memory_written:  Whether the block has written to memory before this read.
        :return:                The value, or None if it is unknown.
        """
        space_name = varnode.space.name
        if space_name == "const":
            return claripy.BVV(varnode.offset, varnode.size * 8)
        if space_name.lower() in MEMORY_SPACES:
            return self._load(varnode.offset, varnode.size, memory_written)
        return values.get(self._varnode_key(varnode))

    def _load(self, addr: int, size: int, memory_written: bool) -> BV | None:
        """
        Read a value out of the loaded image, if it is one that may be assumed constant.

        :param addr:            The address to read from.
        :param size:            The number of bytes to read.
        :param memory_written:  Whether the block has written to memory before this read.
        :return:                The value, or None if it may not be assumed constant.
        """
        if size not in LOADABLE_SIZES or not self._load_callback(addr, size):
            return None
        if memory_written and not self._is_write_protected(addr):
            return None
        try:
            value = self.project.loader.memory.unpack_word(addr, size=size, endness=self.project.arch.memory_endness)
        except KeyError:
            return None
        return claripy.BVV(value, size * 8)

    def _is_write_protected(self, addr: int) -> bool:
        """
        Check whether an address lies in a region that the program cannot write to, which makes its content
        independent of anything the block stored.

        :param addr:    The address to check.
        :return:        True if the address is mapped and not writable.
        """
        region = self.project.loader.find_section_containing(addr)
        if region is None:
            region = self.project.loader.find_segment_containing(addr)
        return region is not None and not region.is_writable

    @staticmethod
    def _write(values: dict[VarnodeKey, BV], varnode: Varnode, value: BV | None) -> None:
        """
        Record the value of a varnode, dropping every value it overlaps. Register spaces alias, so a write to a
        sub-register must not leave a stale value of the register containing it behind.

        :param values:      Concrete values of the varnodes defined so far in the block.
        :param varnode:     The varnode written to.
        :param value:       The value written, or None if it is unknown.
        """
        space_name, offset, size = PcodeConstantResolver._varnode_key(varnode)
        stale = [k for k in values if k[0] == space_name and k[1] < offset + size and offset < k[1] + k[2]]
        for key in stale:
            del values[key]
        if value is not None:
            values[space_name, offset, size] = value

    @staticmethod
    def _varnode_key(varnode: Varnode) -> VarnodeKey:
        return varnode.space.name, varnode.offset, varnode.size

from typing import Optional, Iterable

import claripy
import logging

from angr.engines.engine import SuccessorsMixin, SimSuccessors
from ...utils.constants import DEFAULT_STATEMENT
from ... import sim_options as o
from ... import errors
from .lifter import PcodeLifterEngineMixin, IRSB
from .emulate import PcodeEmulatorMixin

l = logging.getLogger(__name__)

# pylint:disable=abstract-method


class HeavyPcodeMixin(
    SuccessorsMixin,
    PcodeLifterEngineMixin,
    PcodeEmulatorMixin,
):
    """
    Execution engine based on P-code, Ghidra's IR.

    Responds to the following parameters to the step stack:

    - irsb:        The P-Code IRSB object to use for execution. If not provided one will be lifted.
    - skip_stmts:  The number of statements to skip in processing
    - last_stmt:   Do not execute any statements after this statement
    - thumb:       Whether the block should be force to be lifted in ARM's THUMB mode. (FIXME)
    - extra_stop_points:
                   An extra set of points at which to break basic blocks
    - insn_bytes:  A string of bytes to use for the block instead of the project.
    - size:        The maximum size of the block, in bytes.
    - num_inst:    The maximum number of instructions.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._addr = None
        self._insn_bytes = None
        self._thumb = None
        self._size = None
        self._num_inst = None
        self._extra_stop_points = None

    def process_successors(
        self,
        successors: SimSuccessors,
        irsb: Optional[IRSB] = None,
        insn_text: Optional[str] = None,
        insn_bytes: Optional[bytes] = None,
        thumb: bool = False,
        size: Optional[int] = None,
        num_inst: Optional[int] = None,
        extra_stop_points: Optional[Iterable[int]] = None,
        **kwargs,
    ) -> None:
        # pylint:disable=arguments-differ
        if type(successors.addr) is not int:
            return super().process_successors(
                successors,
                extra_stop_points=extra_stop_points,
                num_inst=num_inst,
                size=size,
                insn_text=insn_text,
                insn_bytes=insn_bytes,
                **kwargs,
            )

        if insn_text is not None:
            if insn_bytes is not None:
                raise errors.SimEngineError("You cannot provide both 'insn_bytes' and 'insn_text'!")

            insn_bytes = self.project.arch.asm(insn_text, addr=successors.addr, thumb=thumb)
            if insn_bytes is None:
                raise errors.AngrAssemblyError(
                    "Assembling failed. Please make sure keystone is installed, and the" " assembly string is correct."
                )

        successors.sort = "IRSB"
        successors.description = "IRSB"
        self.state.history.recent_block_count = 1
        self.state.scratch.guard = claripy.true
        self.state.scratch.sim_procedure = None
        addr = successors.addr
        self.state.scratch.bbl_addr = addr
        self.state.scratch.irsb = irsb

        self._addr = addr
        self._insn_bytes = insn_bytes
        self._thumb = thumb
        self._size = size
        self._num_inst = num_inst
        self._extra_stop_points = extra_stop_points

        # Lift and process the block to get successors, retry if necessary
        finished = False
        while not finished:
            self._lift_irsb()
            self._probe_access()
            self._store_successor_artifacts(successors)
            finished = self._process_irsb()

        self._process_successor_exits(successors)
        successors.processed = True

    def _lift_irsb(self):
        irsb = self.state.scratch.irsb
        if irsb is None:
            irsb = self.lift_pcode(
                addr=self._addr,
                state=self.state,
                insn_bytes=self._insn_bytes,
                thumb=self._thumb,
                size=self._size,
                num_inst=self._num_inst,
                extra_stop_points=self._extra_stop_points,
            )
        if irsb.size == 0:
            if irsb.jumpkind == "Ijk_NoDecode" and not self.state.project.is_hooked(irsb.addr):
                raise errors.SimIRSBNoDecodeError(
                    "IR decoding error at %#x. You can hook this instruction with "
                    "a python replacement using project.hook"
                    "(%#x, your_function, length=length_of_instruction)." % (self._addr, self._addr)
                )
            raise errors.SimIRSBError("Empty IRSB passed to HeavyPcodeMixin.")
        self.state.scratch.irsb = irsb

    def _store_successor_artifacts(self, successors: SimSuccessors) -> None:
        """
        Update successors.artifacts with IRSB details.
        """
        irsb = self.state.scratch.irsb
        successors.artifacts["irsb"] = irsb
        successors.artifacts["irsb_size"] = irsb.size
        successors.artifacts["irsb_direct_next"] = irsb.direct_next
        successors.artifacts["irsb_default_jumpkind"] = irsb.jumpkind
        successors.artifacts["insn_addrs"] = []

    def _probe_access(self) -> None:
        """
        Check permissions, are we allowed to execute here? Do we care?
        """
        if o.STRICT_PAGE_ACCESS not in self.state.options:
            return
        try:
            perms = self.state.memory.permissions(self._addr)
        except errors.SimMemoryError:
            raise errors.SimSegfaultError(self._addr, "exec-miss") from errors.SimMemoryError
        else:
            if not perms.symbolic:
                perms = self.state.solver.eval(perms)
                if not perms & 4 and o.ENABLE_NX in self.state.options:
                    raise errors.SimSegfaultError(self._addr, "non-executable")

    def _process_irsb(self) -> bool:
        """
        Execute the IRSB. Returns True if successfully processed.
        """
        try:
            self.handle_pcode_block(self.state.scratch.irsb)
            return True
        except errors.SimReliftException as e:
            self.state = e.state
            if self._insn_bytes is not None:
                raise errors.SimEngineError("You cannot pass self-modifying code as insn_bytes!!!")
            new_ip = self.state.scratch.ins_addr
            if self._size is not None:
                self._size -= new_ip - self._addr
            if self._num_inst is not None:
                self._num_inst -= self.state.scratch.num_insns
            self._addr = new_ip

            # clear the stage before creating the new IRSB
            self.state.scratch.dirty_addrs.clear()
            self.state.scratch.irsb = None
        except errors.SimError as ex:
            ex.record_state(self.state)
            raise
        # FIXME:
        # except VEXEarlyExit:
        #     break
        return False

    def _process_successor_exits(self, successors: SimSuccessors) -> None:
        """
        Do return emulation and call-less stuff.
        """
        for exit_state in list(successors.all_successors):
            exit_jumpkind = exit_state.history.jumpkind
            if exit_jumpkind is None:
                exit_jumpkind = ""

            if o.CALLLESS in self.state.options and exit_jumpkind == "Ijk_Call":
                exit_state.registers.store(
                    exit_state.arch.ret_offset,
                    exit_state.solver.Unconstrained("fake_ret_value", exit_state.arch.bits),
                )
                exit_state.scratch.target = exit_state.solver.BVV(
                    successors.addr + self.state.scratch.irsb.size, exit_state.arch.bits
                )
                exit_state.history.jumpkind = "Ijk_Ret"
                exit_state.regs.ip = exit_state.scratch.target
                if exit_state.arch.call_pushes_ret:
                    exit_state.regs.sp = exit_state.regs.sp + exit_state.arch.bytes

            elif o.DO_RET_EMULATION in exit_state.options and (
                exit_jumpkind == "Ijk_Call" or exit_jumpkind.startswith("Ijk_Sys")
            ):
                l.debug("%s adding postcall exit.", self)

                ret_state = exit_state.copy()
                guard = (
                    ret_state.solver.true
                    if o.TRUE_RET_EMULATION_GUARD in self.state.options
                    else ret_state.solver.false
                )
                ret_target = ret_state.solver.BVV(successors.addr + self.state.scratch.irsb.size, ret_state.arch.bits)
                if ret_state.arch.call_pushes_ret and not exit_jumpkind.startswith("Ijk_Sys"):
                    ret_state.regs.sp = ret_state.regs.sp + ret_state.arch.bytes
                successors.add_successor(
                    ret_state,
                    ret_target,
                    guard,
                    "Ijk_FakeRet",
                    exit_stmt_idx=DEFAULT_STATEMENT,
                    exit_ins_addr=self.state.scratch.ins_addr,
                )

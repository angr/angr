from typing import Optional, TYPE_CHECKING
import logging

import claripy

from ..sim_options import REPLACEMENT_SOLVER
from .plugin import SimStatePlugin

if TYPE_CHECKING:
    from angr import SimState

_l = logging.getLogger(name=__name__)


class SimRebaseableStack(SimStatePlugin):
    def __init__(self, bp=None, bp_value=None):
        super().__init__()
        self.bp: Optional[claripy.ast.Bits] = bp
        self.bp_value: Optional[int] = bp_value

    def set_state(self, state: 'SimState'):

        if REPLACEMENT_SOLVER not in state.options:
            raise ValueError("SimRebaseableStack requires replacement solver to function. Please add "
                             "REPLACEMENT_SOLVER to your state options.")

        super().set_state(state)
        # if the stack pointer is a BVV, replace it with self.sp
        if isinstance(state.regs._sp, claripy.ast.Base) and state.regs._sp.op == "BVV":
            sp_value = state.solver.eval(state.regs._sp)
            bp_value = self._find_actual_bp(sp_value)
            self.bp_value = bp_value
            if self.bp is None:
                self.bp = claripy.BVS("stack_pointer", state.arch.bits)
            state.regs._sp = self.bp + (sp_value - bp_value)
            state.solver._solver.add_replacement(self.bp, self.bp_value, invalidate_cache=False)
            self._rewrite_stack_values(bp_value, bp_value - sp_value + self.state.arch.bytes)
            _l.debug("Initialized the stack pointer to %s. Current value: %#x.",
                     state.regs._sp,
                     sp_value,
                     )

    @SimStatePlugin.memo
    def copy(self, memo): # pylint: disable=unused-argument
        o = SimRebaseableStack(self.bp, self.bp_value)
        return o

    def rebase(self, bp_value: int):
        """
        Rebase the stack from an old value to a new value. The entire stack region will be rebased to the new location.

        :param bp_value:
        :return:
        """

        if bp_value == self.bp_value:
            return
        self.state.solver._solver.remove_replacements({self.bp})

        old_bp_value = self.bp_value
        old_sp_value = self.state.solver.eval(self.state.regs._sp)
        self.bp_value = bp_value
        self._migrate_stack(old_bp_value, bp_value, old_bp_value - old_sp_value + self.state.arch.bytes)
        self.state.solver._solver.add_replacement(self.bp, self.bp_value, invalidate_cache=False)

    def _find_actual_bp(self, sp: int, max_scan: int=65536) -> int:
        """
        Scan the memory region and find the actual base pointer with the help of heuristics.

        :param sp:          The current stack pointer.
        :param max_scan:    The number of bytes to scan upwards from the current sp.
        :return:            The actual base pointer value (that we believe to be).
        """

        candidates = set()

        if self.state.arch.initial_sp is not None:
            if self.state.arch.initial_sp - sp < max_scan:
                candidates.add(self.state.arch.initial_sp)

        candidates.add(sp & 0xffffffffffff0000)

        # return the first address that "starts a stack region": purely symbolic above the region but has bytes below
        # the region
        for cand in candidates:
            b_above = self.state.memory.load(cand + self.state.arch.bytes, size=4)
            b_below = self.state.memory.load(cand - self.state.arch.bytes, size=4)
            if b_above.symbolic and not b_below.symbolic:
                return cand

        _l.warning("Cannot find any candidate that satisfies our heuristics. Returning the initial stack pointer "
                   "directly.")
        return self.state.arch.initial_sp or sp

    def _migrate_stack(self, old_bp: int, new_bp: int, size: int):

        # TODO: Implement region rebasing on the memory level
        block_size = self.state.arch.bytes
        for pos in range(0, size, block_size):
            b = self.state.memory.load(old_bp - pos, size=block_size)
            self.state.memory.store(new_bp - pos, b)

    def _rewrite_stack_values(self, bp: int, size: int):
        block_size = self.state.arch.bytes
        for pos in range(0, size, block_size):
            b = self.state.memory.load(bp - pos, size=block_size, endness=self.state.arch.memory_endness)
            if not b.symbolic:
                v = self.state.solver.eval(b)
                if v - bp < size + 128:
                    self.state.memory.store(self.bp - pos, b, endness=self.state.arch.memory_endness)


from angr.sim_state import SimState
SimState.register_default('rb_stack', SimRebaseableStack)

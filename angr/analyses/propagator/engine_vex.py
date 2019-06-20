
import logging

from ...engines.light import SimEngineLightVEXMixin, SpOffset
from .values import TOP, BOTTOM
from .engine_base import SimEnginePropagatorBase


_l = logging.getLogger(name=__name__)


class SimEnginePropagatorVEX(
    SimEngineLightVEXMixin,
    SimEnginePropagatorBase
):
    #
    # Private methods
    #

    def _process(self, state, successors, block=None, whitelist=None, **kwargs):

        super()._process(state, successors, block=block, whitelist=whitelist, **kwargs)

        if self.block.vex.jumpkind == 'Ijk_Call':
            if self.arch.call_pushes_ret:
                # pop ret from the stack
                sp_offset = self.arch.sp_offset
                sp_value = state.load_register(sp_offset, self.arch.bytes)
                state.store_register(sp_offset, self.arch.bytes, sp_value + self.arch.bytes)

        return state

    def _allow_loading(self, addr, size):
        if self._load_callback is None:
            return True
        return self._load_callback(addr, size)

    #
    # Function handlers
    #

    def _handle_function(self, addr):
        if addr is not None:
            print("calling ", hex(addr))
        # Special handler for getpc()
        if self.arch.name == "X86":
            if addr == 0x537375:  # FIXME: I need a reference to angr Project :(
                ebx_offset = self.arch.registers['ebx'][0]
                self.state.store_register(ebx_offset, 4, self.block.addr + self.block.size)

    #
    # VEX statement handlers
    #

    def _handle_Put(self, stmt):
        size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
        data = self._expr(stmt.data)

        if data is not BOTTOM:
            self.state.store_register(stmt.offset, size, data)

    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        if addr is None:
            return
        size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
        data = self._expr(stmt.data)

        if isinstance(addr, SpOffset):
            # Local variables
            self.state.store_local_variable(addr.offset, size, data)

    #
    # Expression handlers
    #

    def _handle_Get(self, expr):
        size = expr.result_size(self.tyenv) // self.arch.byte_width
        return self.state.load_register(expr.offset, size)

    def _handle_Load(self, expr):

        addr = self._expr(expr.addr)
        if addr in (None, TOP, BOTTOM):
            return
        size = expr.result_size(self.tyenv) // self.arch.byte_width

        if isinstance(addr, SpOffset):
            # Local variables
            return self.state.load_local_variable(addr.offset, size)
        else:
            # try loading from the state
            if self.base_state is not None and self._allow_loading(addr, size):
                print("Loading from ", hex(addr))
                data = self.base_state.memory.load(addr, size, endness=expr.endness)
                if not data.symbolic:
                    return self.base_state.solver.eval(data)

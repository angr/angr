
import logging

import pyvex

from ...engines.light import SimEngineLightVEXMixin, SpOffset
from .values import Top, Bottom
from .engine_base import SimEnginePropagatorBase
from .vex_vars import VEXReg, VEXTmp, VEXMemVar


_l = logging.getLogger(name=__name__)


class SimEnginePropagatorVEX(
    SimEngineLightVEXMixin,
    SimEnginePropagatorBase
):
    #
    # Private methods
    #

    def _process(self, state, successors, block=None, whitelist=None, **kwargs):  # pylint:disable=arguments-differ

        super()._process(state, successors, block=block, whitelist=whitelist, **kwargs)

        if self.block.vex.jumpkind == 'Ijk_Call':
            if self.arch.call_pushes_ret:
                # pop ret from the stack
                sp_offset = self.arch.sp_offset
                sp_value = state.load_register(sp_offset, self.arch.bytes)
                state.store_register(sp_offset, self.arch.bytes, sp_value + self.arch.bytes)

        return state

    def _allow_loading(self, addr, size):
        if type(addr) in (Top, Bottom):
            return False
        if self._load_callback is None:
            return True
        return self._load_callback(addr, size)

    def _expr(self, expr):
        v = super()._expr(expr)

        if v is not None and type(v) not in {Bottom, Top} and v is not expr:
            # Record the replacement
            if type(expr) is pyvex.IRExpr.Get:
                if expr.offset not in (self.arch.sp_offset, self.arch.ip_offset, ):
                    self.state.add_replacement(self._codeloc(block_only=True),
                                               VEXReg(expr.offset, expr.result_size(self.tyenv) // 8),
                                               v)
        return v

    def _load_data(self, addr, size, endness):
        if isinstance(addr, SpOffset):
            # Local variable
            v = self.state.load_local_variable(addr.offset, size)
            return v
        elif isinstance(addr, int):
            # Try loading from the state
            if self.base_state is not None and self._allow_loading(addr, size):
                _l.debug("Loading %d bytes from %x.", size, addr)
                data = self.base_state.memory.load(addr, size, endness=endness)
                if not data.symbolic:
                    return self.base_state.solver.eval(data)
        return None

    #
    # Function handlers
    #

    def _handle_function(self, addr):
        if self.arch.name == "X86":
            try:
                b = self._project.loader.memory.load(addr, 4)
            except KeyError:
                return
            if b == b"\x8b\x1c\x24\xc3":
                # getpc:
                #   mov ebx, [esp]
                #   ret
                ebx_offset = self.arch.registers['ebx'][0]
                self.state.store_register(ebx_offset, 4, self.block.addr + self.block.size)

    #
    # VEX statement handlers
    #

    def _handle_WrTmp(self, stmt):
        super()._handle_WrTmp(stmt)

        if stmt.tmp in self.tmps:
            self.state.add_replacement(self._codeloc(block_only=True), VEXTmp(stmt.tmp), self.tmps[stmt.tmp])

    def _handle_Put(self, stmt):
        size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
        data = self._expr(stmt.data)

        if type(data) is not Bottom:
            self.state.store_register(stmt.offset, size, data)

    def _store_data(self, addr, data, size, endness):
        # pylint: disable=unused-argument,no-self-use
        if isinstance(addr, SpOffset):
            # Local variables
            self.state.store_local_variable(addr.offset, size, data)
        elif isinstance(addr, int):
            # a memory address
            variable = VEXMemVar(addr, size)
            self.state.add_replacement(self._codeloc(block_only=True), variable, data)

    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        if addr is None:
            return
        size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
        data = self._expr(stmt.data)
        self._store_data(addr, data, size, self.arch.memory_endness)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            addr = self._expr(stmt.addr)
            if addr is not None:
                self.tmps[stmt.dst] = self._load_data(addr, stmt.alt.result_size(self.tyenv) // 8,
                                                      self.arch.memory_endness)
        elif guard is False:
            data = self._expr(stmt.alt)
            self.tmps[stmt.dst] = data
        else:
            self.tmps[stmt.dst] = None

        # add replacement
        if stmt.dst in self.tmps and self.tmps[stmt.dst]:
            self.state.add_replacement(self._codeloc(block_only=True), VEXTmp(stmt.dst), self.tmps[stmt.dst])

    def _handle_StoreG(self, stmt):

        guard = self._expr(stmt.guard)
        data = self._expr(stmt.data)
        if guard is True:
            addr = self._expr(stmt.addr)
            if addr is not None:
                self._store_data(addr, data, stmt.data.result_size(self.tyenv) // 8, self.arch.memory_endness)

        #elif guard is False:
        #    data = self._expr(stmt.alt)
        #    self.tmps[stmt.dst] = data
        #else:
        #    self.tmps[stmt.dst] = None

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        if stmt.storedata is None:
            # load-link
            addr = self._expr(stmt.addr)
            size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
            data = self._load_data(addr, size, stmt.endness)
            if data is not None:
                self.tmps[stmt.result] = data
            if stmt.result in self.tmps:
                self.state.add_replacement(self._codeloc(block_only=True),
                                           VEXTmp(stmt.result),
                                           self.tmps[stmt.result])
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            if storedata is not None:
                addr = self._expr(stmt.addr)
                size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width
                self._store_data(addr, storedata, size, stmt.endness)

            self.tmps[stmt.result] = 1
            self.state.add_replacement(self._codeloc(block_only=True),
                                       VEXTmp(stmt.result),
                                       self.tmps[stmt.result])

    #
    # Expression handlers
    #

    def _handle_Get(self, expr):
        size = expr.result_size(self.tyenv) // self.arch.byte_width
        return self.state.load_register(expr.offset, size)

    def _handle_Load(self, expr):

        addr = self._expr(expr.addr)
        if addr is None or type(addr) in (Top, Bottom):
            return None
        size = expr.result_size(self.tyenv) // self.arch.byte_width

        return self._load_data(addr, size, expr.endness)

    def _handle_CCall(self, expr):
        return None

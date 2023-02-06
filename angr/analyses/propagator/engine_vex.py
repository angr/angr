from typing import TYPE_CHECKING
import logging

import claripy
import pyvex

from ...engines.light import SimEngineLightVEXMixin
from ...calling_conventions import DEFAULT_CC, SimRegArg
from .values import Top, Bottom
from .engine_base import SimEnginePropagatorBase
from .top_checker_mixin import TopCheckerMixin
from .vex_vars import VEXReg, VEXTmp, VEXMemVar

if TYPE_CHECKING:
    from angr.analyses.propagator.propagator import PropagatorVEXState


_l = logging.getLogger(name=__name__)


class SimEnginePropagatorVEX(
    TopCheckerMixin,
    SimEngineLightVEXMixin,
    SimEnginePropagatorBase,
):
    state: "PropagatorVEXState"

    #
    # Private methods
    #

    def _process(self, state, successors, block=None, whitelist=None, **kwargs):  # pylint:disable=arguments-differ
        super()._process(state, successors, block=block, whitelist=whitelist, **kwargs)

        if self.block.vex.jumpkind == "Ijk_Call":
            if self.arch.call_pushes_ret:
                # pop ret from the stack
                sp_offset = self.arch.sp_offset
                sp_value = state.load_register(sp_offset, self.arch.bytes)
                if sp_value is not None:
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
                if expr.offset not in (
                    self.arch.sp_offset,
                    self.arch.ip_offset,
                ):
                    self.state.add_replacement(
                        self._codeloc(block_only=False), VEXReg(expr.offset, expr.result_size(self.tyenv) // 8), v
                    )
        return v

    def _load_data(self, addr, size, endness):
        if isinstance(addr, claripy.ast.Base):
            sp_offset = self.extract_offset_to_sp(addr)
            if sp_offset is not None:
                # Local variable
                v = self.state.load_local_variable(sp_offset, size, endness)
                return v
            elif addr.op == "BVV":
                addr = addr.args[0]
                # Try loading from the state
                if self._allow_loading(addr, size):
                    if self.base_state is not None:
                        _l.debug("Loading %d bytes from %x.", size, addr)
                        data = self.base_state.memory.load(addr, size, endness=endness)
                        if not data.symbolic:
                            return data
                    else:
                        try:
                            val = self.project.loader.memory.unpack_word(addr, size=size, endness=endness)
                            return claripy.BVV(val, size * self.arch.byte_width)
                        except KeyError:
                            return None
        return None

    #
    # Function handlers
    #

    def _handle_function(self, addr):
        if self.arch.name == "X86":
            if isinstance(addr, claripy.ast.Base) and addr.op == "BVV":
                try:
                    b = self._project.loader.memory.load(addr.args[0], 4)
                except KeyError:
                    return
                except TypeError:
                    return

                if b == b"\x8b\x1c\x24\xc3":
                    # getpc:
                    #   mov ebx, [esp]
                    #   ret
                    ebx_offset = self.arch.registers["ebx"][0]
                    self.state.store_register(ebx_offset, 4, claripy.BVV(self.block.addr + self.block.size, 32))
        if self.arch.name in DEFAULT_CC:
            cc = DEFAULT_CC[self.arch.name]  # don't instantiate the class for speed
            if isinstance(cc.RETURN_VAL, SimRegArg):
                offset, size = self.arch.registers[cc.RETURN_VAL.reg_name]
                self.state.store_register(offset, size, self.state.top(size * self.arch.byte_width))
            if cc.CALLER_SAVED_REGS:
                for reg_name in cc.CALLER_SAVED_REGS:
                    offset, size = self.arch.registers[reg_name]
                    self.state.store_register(offset, size, self.state.top(size * self.arch.byte_width))

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

        if not (data is None or self.state.is_top(data)) or self.state._store_tops:
            if data is None:
                # make sure it's a top
                data = self.state.top(size * self.arch.byte_width)
            self.state.store_register(stmt.offset, size, data)
            self.state.add_replacement(self._codeloc(block_only=False), VEXReg(stmt.offset, size), data)

    def _store_data(self, addr, data, size, endness):
        # pylint: disable=unused-argument,no-self-use
        if isinstance(addr, claripy.ast.Base):
            sp_offset = self.extract_offset_to_sp(addr)
            if sp_offset is not None:
                # Local variables
                self.state.store_local_variable(sp_offset, size, data, endness)
            elif addr.op == "BVV":
                # a memory address
                addr = addr.args[0]
                variable = VEXMemVar(addr, size)
                self.state.add_replacement(self._codeloc(block_only=False), variable, data)

    def _handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        if self.state.is_top(addr):
            return
        size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
        data = self._expr(stmt.data)

        if not (data is None or self.state.is_top(data)) or self.state._store_tops:
            if data is None:
                # make sure it's a top
                data = self.state.top(size * self.arch.byte_width)
            self._store_data(addr, data, size, self.arch.memory_endness)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            addr = self._expr(stmt.addr)
            if addr is not None:
                self.tmps[stmt.dst] = self._load_data(
                    addr, stmt.alt.result_size(self.tyenv) // 8, self.arch.memory_endness
                )
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

        # elif guard is False:
        #    data = self._expr(stmt.alt)
        #    self.tmps[stmt.dst] = data
        # else:
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
                self.state.add_replacement(self._codeloc(block_only=True), VEXTmp(stmt.result), self.tmps[stmt.result])
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            if storedata is not None:
                addr = self._expr(stmt.addr)
                size = storedata.size() // self.arch.byte_width
                self._store_data(addr, storedata, size, stmt.endness)

            self.tmps[stmt.result] = 1
            self.state.add_replacement(self._codeloc(block_only=True), VEXTmp(stmt.result), self.tmps[stmt.result])

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

    def _handle_Binop(self, expr: pyvex.IRExpr.Binop):
        if not self.state.do_binops:
            return self.state.top(expr.result_size(self.tyenv))

        r = super()._handle_Binop(expr)
        # print(expr.op, r)
        return r

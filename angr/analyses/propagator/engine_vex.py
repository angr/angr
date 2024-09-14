from __future__ import annotations
from typing import TYPE_CHECKING
import logging

import claripy
import pyvex
import archinfo

from angr.knowledge_plugins.propagations.states import RegisterAnnotation, RegisterComparisonAnnotation
from ...engines.light import SimEngineLightVEXMixin
from ...calling_conventions import DEFAULT_CC, SYSCALL_CC, default_cc, SimRegArg
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
    state: PropagatorVEXState

    #
    # Private methods
    #

    def _process_block_end(self):
        super()._process_block_end()
        if self.block.vex.jumpkind == "Ijk_Call" and self.arch.call_pushes_ret:
            # pop ret from the stack
            sp_offset = self.arch.sp_offset
            sp_value = self.state.load_register(sp_offset, self.arch.bytes)
            if sp_value is not None:
                self.state.store_register(sp_offset, self.arch.bytes, sp_value + self.arch.bytes)

        if self.block.vex.jumpkind == "Ijk_Call" or self.block.vex.jumpkind.startswith("Ijk_Sys"):
            self._handle_return_from_call()

    def _allow_loading(self, addr, size):
        if type(addr) in (Top, Bottom):
            return False
        if self._load_callback is None:
            return True
        return self._load_callback(addr, size)

    def _expr(self, expr):
        v = super()._expr(expr)

        if (
            v is not None
            and type(v) not in {Bottom, Top}
            and v is not expr
            and type(expr) is pyvex.IRExpr.Get
            and expr.offset
            not in (
                self.arch.sp_offset,
                self.arch.ip_offset,
            )
        ):
            # Record the replacement
            self.state.add_replacement(
                self._codeloc(block_only=False), VEXReg(expr.offset, expr.result_size(self.tyenv) // 8), v
            )
        return v

    def _load_data(self, addr, size, endness):
        if isinstance(addr, claripy.ast.Base):
            sp_offset = self.extract_offset_to_sp(addr)
            if sp_offset is not None:
                # Local variable
                return self.state.load_local_variable(sp_offset, size, endness)
            if addr.op == "BVV":
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
        if self.arch.name == "X86" and isinstance(addr, claripy.ast.Base) and addr.op == "BVV":
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

    def _handle_return_from_call(self):
        # FIXME: Handle the specific function calling convention when known
        syscall = self.block.vex.jumpkind.startswith("Ijk_Sys")
        cc_map = SYSCALL_CC if syscall else DEFAULT_CC
        if self.arch.name in cc_map:
            cc = default_cc(
                self.arch.name,
                platform=self.project.simos.name if self.project.simos is not None else None,
                syscall=syscall,
            )  # don't instantiate the class for speed
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
    def _handle_Dirty(self, stmt):
        # For RISCV CSR and mret operations, the Dirty statement is skipped.
        if archinfo.arch_riscv64.is_riscv_arch(self.project.arch):
            helper = str(stmt.cee)
            if helper in (
                "riscv_dirtyhelper_CSR_rw",
                "riscv_dirtyhelper_CSR_s",
                "riscv_dirtyhelper_CSR_c",
                "riscv_dirtyhelper_mret",
            ):
                pass
            else:
                self.l.warning("Unimplemented Dirty node for current architecture.")

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

    def _handle_PutI(self, stmt):
        self._expr(stmt.data)

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
        if self.tmps.get(stmt.dst):
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

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = self._expr(expr.args[0]), self._expr(expr.args[1])
        if arg1 is not None and arg1.concrete and arg0 is not None and len(arg0.annotations) == 1:
            anno = arg0.annotations[0]
            if isinstance(anno, RegisterAnnotation):
                cmp_anno = RegisterComparisonAnnotation(anno.offset, anno.size, "eq", arg1.concrete_value)
                bits = expr.result_size(self.tyenv)
                return self.state.top(bits).annotate(cmp_anno)
        return super()._handle_CmpEQ(expr)

    #
    # Expression handlers
    #

    def _handle_Get(self, expr):
        size = expr.result_size(self.tyenv) // self.arch.byte_width
        return self.state.load_register(expr.offset, size)

    def _handle_GetI(self, expr):
        return self.state.top(expr.result_size(self.tyenv))

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

        return super()._handle_Binop(expr)
        # print(expr.op, r)

    def _handle_Triop(self, expr: pyvex.IRExpr.Triop):
        if not self.state.do_binops:
            return self.state.top(expr.result_size(self.tyenv))

        return super()._handle_Triop(expr)

    def _handle_Conversion(self, expr):
        expr_ = self._expr(expr.args[0])
        to_size = expr.result_size(self.tyenv)
        if expr_ is None:
            return self._top(to_size)
        if self._is_top(expr_):
            return self._top(to_size).annotate(*expr_.annotations)

        if isinstance(expr_, claripy.ast.Base) and expr_.op == "BVV":
            if expr_.size() > to_size:
                # truncation
                return expr_[to_size - 1 : 0]
            if expr_.size() < to_size:
                # extension
                return claripy.ZeroExt(to_size - expr_.size(), expr_)
            return expr_

        return self._top(to_size)

    def _handle_Exit(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is not None and len(guard.annotations) == 1:
            dst = self._expr(stmt.dst)
            if dst is not None and dst.concrete:
                anno = guard.annotations[0]
                if isinstance(anno, RegisterComparisonAnnotation) and anno.cmp_op == "eq":
                    v = (anno.offset, anno.size, anno.value)
                    if v not in self.state.block_initial_reg_values[self.block.addr, dst.concrete_value]:
                        self.state.block_initial_reg_values[self.block.addr, dst.concrete_value].append(v)

        super()._handle_Exit(stmt)

    _handle_CmpF = _handle_CmpEQ

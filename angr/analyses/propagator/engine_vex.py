# pylint: disable=missing-class-docstring
from __future__ import annotations
from typing import cast
import logging

import claripy
import pyvex

from angr.engines.vex.claripy.datalayer import value
from angr.knowledge_plugins.propagations.states import RegisterAnnotation, RegisterComparisonAnnotation
from angr.engines.light import SimEngineNostmtVEX
from angr.calling_conventions import DEFAULT_CC, SYSCALL_CC, default_cc, SimRegArg
from angr.analyses.propagator.propagator import PropagatorVEXState
from angr.block import Block
from .engine_base import SimEnginePropagatorBaseMixin
from .top_checker_mixin import ClaripyDataVEXEngineMixin
from .vex_vars import VEXReg, VEXTmp, VEXMemVar


_l = logging.getLogger(name=__name__)

dirty_handler = SimEngineNostmtVEX[PropagatorVEXState, claripy.ast.BV, PropagatorVEXState].dirty_handler
binop_handler = SimEngineNostmtVEX[PropagatorVEXState, claripy.ast.BV, PropagatorVEXState].binop_handler


class SimEnginePropagatorVEX(
    ClaripyDataVEXEngineMixin[PropagatorVEXState, claripy.ast.BV, PropagatorVEXState, None],
    SimEnginePropagatorBaseMixin[PropagatorVEXState, claripy.ast.BV, Block],
    SimEngineNostmtVEX[PropagatorVEXState, claripy.ast.BV, PropagatorVEXState],
):
    @dirty_handler
    def _handle_dirty_noop(self, expr):
        if expr.tmp not in (-1, 0xFFFFFFFF):
            self.tmps[expr.tmp] = self._top(pyvex.get_type_size(self.tyenv.lookup(expr.tmp)))

    _handle_dirty_riscv_dirtyhelper_CSR_rw = _handle_dirty_noop
    _handle_dirty_riscv_dirtyhelper_CSR_s = _handle_dirty_noop
    _handle_dirty_riscv_dirtyhelper_CSR_c = _handle_dirty_noop
    _handle_dirty_riscv_dirtyhelper_mret = _handle_dirty_noop

    #
    # Private methods
    #

    def _process_block_end(self, stmt_result, whitelist):
        return self.state

    def _process_block(self, whitelist=None):
        result = super()._process_block(whitelist)
        if self.block.vex.jumpkind == "Ijk_Call" and self.arch.call_pushes_ret:
            # pop ret from the stack
            sp_offset = self.arch.sp_offset
            sp_value = self.state.load_register(sp_offset, self.arch.bytes)
            if sp_value is not None:
                self.state.store_register(sp_offset, self.arch.bytes, sp_value + self.arch.bytes)

        if self.block.vex.jumpkind == "Ijk_Call" or self.block.vex.jumpkind.startswith("Ijk_Sys"):
            self._handle_return_from_call()
        return result

    def _allow_loading(self, addr: claripy.ast.BV, size):
        if self._is_top(addr):
            return False
        if self._load_callback is None:
            return True
        return self._load_callback(addr, size)

    def _load_data(self, addr: claripy.ast.BV, size, endness) -> claripy.ast.BV:
        sp_offset = self.extract_offset_to_sp(addr)
        if sp_offset is not None:
            # Local variable
            return self.state.load_local_variable(sp_offset, size, endness)
        if addr.op == "BVV" and self._allow_loading(addr, size):
            # Try loading from the state
            addr_int = cast(int, addr.args[0])
            if self.base_state is not None:
                _l.debug("Loading %d bytes from %x.", size, addr_int)
                data = self.base_state.memory.load(addr, size, endness=endness)
                if not data.symbolic:
                    return data
            else:
                try:
                    val = self.project.loader.memory.unpack_word(addr_int, size=size, endness=endness)
                    return claripy.BVV(val, size * self.arch.byte_width)
                except KeyError:
                    pass
        return self._top(size * self.arch.byte_width)

    #
    # Function handlers
    #

    def _handle_function(self, addr):
        if self.arch.name == "X86" and isinstance(addr, claripy.ast.Base) and addr.op == "BVV":
            try:
                b = self.project.loader.memory.load(addr.args[0], 4)
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
            assert cc is not None
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

    def _handle_stmt_WrTmp(self, stmt):
        self.tmps[stmt.tmp] = self._expr(stmt.data)
        if stmt.tmp in self.tmps:
            self.state.add_replacement(self._codeloc(block_only=True), VEXTmp(stmt.tmp), self.tmps[stmt.tmp])

    def _handle_stmt_Put(self, stmt):
        size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
        data = self._expr(stmt.data)

        if not self._is_top(data) or self.state._store_tops:
            self.state.store_register(stmt.offset, size, data)
            self.state.add_replacement(self._codeloc(block_only=False), VEXReg(stmt.offset, size), data)

    def _handle_stmt_PutI(self, stmt):
        self._expr(stmt.data)

    def _store_data(self, addr: claripy.ast.BV, data: claripy.ast.Bits, size: int, endness: str):
        sp_offset = self.extract_offset_to_sp(addr)
        if sp_offset is not None:
            # Local variables
            self.state.store_local_variable(sp_offset, size, data, endness)
        elif addr.op == "BVV":
            # a memory address
            addr_int = cast(int, addr.args[0])
            variable = VEXMemVar(addr_int, size)
            self.state.add_replacement(self._codeloc(block_only=False), variable, data)

    def _handle_stmt_Store(self, stmt):
        addr = self._expr_bv(stmt.addr)
        if self.state.is_top(addr):
            return
        size = stmt.data.result_size(self.tyenv) // self.arch.byte_width
        data = self._expr(stmt.data)

        if not self.state.is_top(data) or self.state._store_tops:
            self._store_data(addr, data, size, self.arch.memory_endness)

    def _handle_stmt_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            addr = self._expr_bv(stmt.addr)
            if addr is not None:
                self.tmps[stmt.dst] = self._load_data(
                    addr, stmt.alt.result_size(self.tyenv) // 8, self.arch.memory_endness
                )
        elif guard is False:
            data = self._expr(stmt.alt)
            self.tmps[stmt.dst] = data
        else:
            self.tmps[stmt.dst] = self._top(stmt.alt.result_size(self.tyenv))

        # add replacement
        if not self._is_top(self.tmps[stmt.dst]):
            self.state.add_replacement(self._codeloc(block_only=True), VEXTmp(stmt.dst), self.tmps[stmt.dst])

    def _handle_stmt_StoreG(self, stmt):
        guard = self._expr_bv(stmt.guard)
        data = self._expr(stmt.data)
        if (guard != 0).is_true():
            addr = self._expr_bv(stmt.addr)
            self._store_data(addr, data, stmt.data.result_size(self.tyenv) // 8, self.arch.memory_endness)

    def _handle_stmt_LLSC(self, stmt):
        if stmt.storedata is None:
            # load-link
            addr = self._expr_bv(stmt.addr)
            size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
            data = self._load_data(addr, size, stmt.endness)
            self.tmps[stmt.result] = data
            if stmt.result in self.tmps:
                self.state.add_replacement(self._codeloc(block_only=True), VEXTmp(stmt.result), self.tmps[stmt.result])
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            addr = self._expr_bv(stmt.addr)
            size = storedata.size() // self.arch.byte_width
            self._store_data(addr, storedata, size, stmt.endness)

            self.tmps[stmt.result] = claripy.BVV(1, 1)
            self.state.add_replacement(self._codeloc(block_only=True), VEXTmp(stmt.result), self.tmps[stmt.result])

    @binop_handler
    def _handle_binop_CmpEQ(self, expr):
        lhs, rhs = self._expr(expr.args[0]), self._expr(expr.args[1])
        if rhs.concrete and len(lhs.annotations) == 1:
            anno = lhs.annotations[0]
            if isinstance(anno, RegisterAnnotation):
                cmp_anno = RegisterComparisonAnnotation(anno.offset, anno.size, "eq", rhs.concrete_value)
                bits = pyvex.get_type_size(pyvex.get_op_retty(expr.op))
                return self.state.top(bits).annotate(cmp_anno)
        if lhs.concrete and len(rhs.annotations) == 1:
            anno = rhs.annotations[0]
            if isinstance(anno, RegisterAnnotation):
                cmp_anno = RegisterComparisonAnnotation(anno.offset, anno.size, "eq", lhs.concrete_value)
                bits = pyvex.get_type_size(pyvex.get_op_retty(expr.op))
                return self.state.top(bits).annotate(cmp_anno)
        return super()._handle_binop_CmpEQ(expr)

    #
    # Expression handlers
    #

    def _handle_expr_Get(self, expr):
        size = expr.result_size(self.tyenv) // self.arch.byte_width
        result = self.state.load_register(expr.offset, size)
        if not self._is_top(result) and expr.offset not in (
            self.arch.sp_offset,
            self.arch.ip_offset,
        ):
            # Record the replacement
            self.state.add_replacement(
                self._codeloc(block_only=False), VEXReg(expr.offset, expr.result_size(self.tyenv) // 8), result
            )
        return result

    def _handle_expr_GetI(self, expr):
        return self.state.top(expr.result_size(self.tyenv))

    def _handle_expr_ITE(self, expr):
        return self.state.top(expr.result_size(self.tyenv))

    def _handle_expr_GSPTR(self, expr):
        return self.state.top(expr.result_size(self.tyenv))

    def _handle_expr_VECRET(self, expr):
        return self.state.top(expr.result_size(self.tyenv))

    def _handle_expr_RdTmp(self, expr):
        try:
            return self.tmps[expr.tmp]
        except KeyError:
            return self._top(pyvex.get_type_size(self.tyenv.lookup(expr.tmp)))

    def _handle_expr_Const(self, expr):
        result = value(expr.con.type, expr.con.value)
        if isinstance(result, claripy.ast.FP):
            return self._top(expr.con.size)
        return result

    def _handle_expr_Load(self, expr):
        addr = self._expr_bv(expr.addr)
        size = expr.result_size(self.tyenv) // self.arch.byte_width
        return self._load_data(addr, size, expr.endness)

    def _handle_expr_Binop(self, expr):
        if not self.state.do_binops:
            return self._top(expr.result_size(self.tyenv))

        return super()._handle_expr_Binop(expr)

    def _handle_expr_Triop(self, expr):
        if not self.state.do_binops:
            return self._top(expr.result_size(self.tyenv))

        return super()._handle_expr_Triop(expr)

    def _handle_stmt_Exit(self, stmt: pyvex.stmt.Exit):
        guard = self._expr(stmt.guard)
        if len(guard.annotations) == 1:
            dst = value(stmt.dst.type, stmt.dst.value)
            if dst.concrete:
                anno = guard.annotations[0]
                if isinstance(anno, RegisterComparisonAnnotation) and anno.cmp_op == "eq":
                    v = (anno.offset, anno.size, anno.value)
                    if v not in self.state.block_initial_reg_values[self.block.addr, dst.concrete_value]:
                        self.state.block_initial_reg_values[self.block.addr, dst.concrete_value].append(v)

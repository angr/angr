# pylint:disable=unused-argument
from __future__ import annotations
from typing import cast, TYPE_CHECKING

import claripy
import pyvex
from archinfo.arch_arm import is_arm_arch

from angr.block import Block
from angr.errors import SimMemoryMissingError
from angr.calling_conventions import SimRegArg, SimStackArg, SimTypeFunction, default_cc
from angr.engines.vex.claripy.datalayer import value as claripy_value
from angr.engines.light import SimEngineNostmtVEX
from angr.knowledge_plugins import Function
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.analyses.typehoon import typevars, typeconsts
from angr.sim_type import SimTypeBottom
from .engine_base import SimEngineVRBase, RichR
from .irsb_scanner import VEXIRSBScanner

if TYPE_CHECKING:
    pass

binop_handler = SimEngineNostmtVEX[
    "VariableRecoveryFastState", RichR[claripy.ast.BV | claripy.ast.FP], None
].binop_handler


class SimEngineVRVEX(
    SimEngineNostmtVEX["VariableRecoveryFastState", RichR[claripy.ast.BV | claripy.ast.FP], None],
    SimEngineVRBase["VariableRecoveryFastState", Block],
):
    """
    Implements the VEX engine for variable recovery analysis.
    """

    reg_read_stmts_to_ignore: set[int]
    stmts_to_lower: set[int]

    def __init__(self, *args, call_info=None, **kwargs):
        super().__init__(*args, **kwargs)

        self.call_info = call_info or {}

    # Statement handlers

    def _is_top(self, expr: RichR) -> bool:
        return self.state.is_top(expr)

    def _top(self, bits: int) -> RichR[claripy.ast.BV]:
        return RichR(self.state.top(bits))

    def _process_block(self, whitelist=None):
        scanner = VEXIRSBScanner(self.project, logger=self.l)
        scanner.process(None, block=self.block)
        self.stmts_to_lower = scanner.stmts_to_lower
        self.reg_read_stmts_to_ignore = scanner.reg_read_stmts_to_ignore

        return super()._process_block(whitelist=whitelist)

    def _handle_stmt_WrTmp(self, stmt):
        self.tmps[stmt.tmp] = self._expr(stmt.data)

    def _handle_stmt_Put(self, stmt):
        offset = stmt.offset
        r = self._expr(stmt.data)
        size = stmt.data.result_size(self.tyenv) // 8

        if offset == self.arch.ip_offset:
            return
        self._assign_to_register(offset, r, size)

    def _handle_stmt_Store(self, stmt):
        addr_r = self._expr_bv(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        r = self._expr(stmt.data)

        self._store(addr_r, r, size, atom=stmt)

    def _handle_stmt_StoreG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            addr = self._expr_bv(stmt.addr)
            size = stmt.data.result_size(self.tyenv) // 8
            data = self._expr(stmt.data)
            self._store(addr, data, size, atom=stmt)

    def _handle_stmt_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            addr = self._expr_bv(stmt.addr)
            if addr is not None:
                self.tmps[stmt.dst] = self._load(addr, self.tyenv.sizeof(stmt.dst) // 8)
        elif guard is False:
            data = self._expr(stmt.alt)
            self.tmps[stmt.dst] = data
        else:
            self.tmps[stmt.dst] = self._top(pyvex.get_type_size(self.tyenv.lookup(stmt.dst)))

    def _handle_stmt_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        if stmt.storedata is None:
            # load-link
            addr = self._expr_bv(stmt.addr)
            size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
            data = self._load(addr, size)
            self.tmps[stmt.result] = data
        else:
            # store-conditional
            assert isinstance(stmt.storedata, pyvex.expr.RdTmp)
            storedata = self._expr(stmt.storedata)
            addr = self._expr_bv(stmt.addr)
            size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width

            self._store(addr, storedata, size)

            result_size = self.tyenv.sizeof(stmt.result)
            self.tmps[stmt.result] = RichR(claripy.BVV(1, result_size))

    # Expression handlers

    def _expr_bv(self, expr) -> RichR[claripy.ast.BV]:
        result = self._expr(expr)
        assert isinstance(result.data, claripy.ast.BV)
        return cast(RichR[claripy.ast.BV], result)

    def _expr_fp(self, expr) -> RichR[claripy.ast.FP]:
        result = self._expr(expr)
        assert isinstance(result.data, claripy.ast.FP)
        return cast(RichR[claripy.ast.FP], result)

    def _handle_expr_Get(self, expr):
        reg_offset = expr.offset
        reg_size = expr.result_size(self.tyenv) // 8

        # because of how VEX implements MOVCC and MOVCS instructions in ARM THUMB mode, we need to skip the register
        # read if the immediate next instruction is an WrTmp(ITE).
        #
        # MOVCC           R3, #0
        #
        #    46 | ------ IMark(0xfeca2, 2, 1) ------
        #    47 | t299 = CmpLT32U(t8,0x00010000)
        #    48 | t143 = GET:I32(r3)      <-   this read does not exist
        #    49 | t300 = ITE(t299,0x00000000,t143)
        #    50 | PUT(r3) = t300
        #    51 | PUT(pc) = 0x000feca5
        if is_arm_arch(self.arch) and (self.ins_addr & 1) == 1 and self.stmt_idx < len(self.block.vex.statements) - 1:
            next_stmt = self.block.vex.statements[self.stmt_idx + 1]
            if isinstance(next_stmt, pyvex.IRStmt.WrTmp) and isinstance(next_stmt.data, pyvex.IRExpr.ITE):
                return RichR(self.state.top(reg_size * 8))

        force_variable_size = None
        if self.stmts_to_lower and self.stmt_idx in self.stmts_to_lower and reg_size == 8:
            force_variable_size = 4

        return self._read_from_register(
            reg_offset,
            reg_size,
            expr=expr,
            force_variable_size=force_variable_size,
            create_variable=self.stmt_idx not in self.reg_read_stmts_to_ignore,
        )

    def _handle_expr_GetI(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_expr_ITE(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_expr_GSPTR(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_expr_VECRET(self, expr):
        return self._top(expr.result_size(self.tyenv))

    def _handle_expr_Load(self, expr: pyvex.IRExpr.Load) -> RichR:
        addr = self._expr_bv(expr.addr)
        size = expr.result_size(self.tyenv) // 8

        return self._load(addr, size)

    def _handle_expr_CCall(self, expr):  # pylint:disable=useless-return
        # ccalls don't matter
        return RichR(self.state.top(expr.result_size(self.tyenv)))

    def _handle_conversion(self, from_size, to_size, signed, operand) -> RichR:
        _ = self._expr(operand)
        return RichR(self.state.top(to_size))

    # Function handlers

    def _handle_function_concrete(self, func: Function):
        if func.prototype is None or func.calling_convention is None:
            return

        try:
            arg_locs = func.calling_convention.arg_locs(func.prototype)
        except (TypeError, ValueError):
            func.prototype = None
            return

        if None in arg_locs:
            return

        for arg_loc in arg_locs:
            for loc in arg_loc.get_footprint():
                if isinstance(loc, SimRegArg):
                    self._read_from_register(self.arch.registers[loc.reg_name][0] + loc.reg_offset, loc.size)
                elif isinstance(loc, SimStackArg):
                    try:
                        sp: MultiValues = self.state.register_region.load(self.arch.sp_offset, self.arch.bytes)
                    except SimMemoryMissingError:
                        pass
                    else:
                        one_sp = sp.one_value()
                        if one_sp is not None:
                            addr = RichR(loc.stack_offset + one_sp)
                            self._load(addr, loc.size)

        # clobber caller-saved registers
        for reg_name in func.calling_convention.CALLER_SAVED_REGS:
            reg_offset, reg_size = self.arch.registers[reg_name]
            self._assign_to_register(reg_offset, self._top(reg_size * self.arch.byte_width), reg_size)

    def _process_block_end(self, stmt_result, whitelist):
        # handles block-end calls
        has_call = False
        current_addr = self.state.block_addr
        for target_func in self.call_info.get(current_addr, []):
            self._handle_function_concrete(target_func)
            has_call = True

        if has_call or self.block.vex.jumpkind == "Ijk_Call":
            # emulates return values from calls
            cc = None
            proto: SimTypeFunction | None = None
            for target_func in self.call_info.get(self.state.block_addr, []):
                if target_func.calling_convention is not None:
                    cc = target_func.calling_convention
                    proto = target_func.prototype
                    break
            if cc is None:
                cc = default_cc(self.arch.name, platform=self.project.simos.name)(self.arch)

            if proto is not None and not isinstance(proto.returnty, SimTypeBottom):
                ret_reg = cc.return_val(proto.returnty)
            else:
                ret_reg = cc.RETURN_VAL
            if isinstance(ret_reg, SimRegArg):
                reg_offset, reg_size = self.arch.registers[ret_reg.reg_name]
                data = self._top(reg_size * self.arch.byte_width)
                self._assign_to_register(reg_offset, data, reg_size, create_variable=False)

                # handle tail-call optimizations
                if self.block.vex.jumpkind == "Ijk_Boring":
                    self.state.ret_val_size = (
                        reg_size if self.state.ret_val_size is None else max(self.state.ret_val_size, reg_size)
                    )

        elif self.block.vex.jumpkind == "Ijk_Ret":
            # handles return statements

            # determine the size of the return register
            # TODO: Handle multiple return registers
            cc = self.state.function.calling_convention
            if cc is None:
                cc_cls = default_cc(self.arch.name, platform=self.project.simos.name)
                assert cc_cls is not None
                cc = cc_cls(self.arch)
            if isinstance(cc.RETURN_VAL, SimRegArg):
                ret_val_size = 0
                reg_offset = cc.RETURN_VAL.check_offset(self.arch)
                for i in range(cc.RETURN_VAL.size):
                    try:
                        _ = self.state.register_region.load(reg_offset + i, 1)
                        ret_val_size = i + 1
                    except SimMemoryMissingError:
                        break
                self.state.ret_val_size = (
                    ret_val_size if self.state.ret_val_size is None else max(self.state.ret_val_size, ret_val_size)
                )

    def _handle_expr_Const(self, expr):
        return RichR(
            claripy_value(expr.con.type, expr.con.value, size=expr.con.size), typevar=typeconsts.int_type(expr.con.size)
        )

    def _handle_expr_RdTmp(self, expr):
        try:
            return self.tmps[expr.tmp]
        except KeyError:
            return self._top(expr.result_size(self.tyenv))

    def _expr_pair(
        self, arg0: pyvex.expr.IRExpr, arg1: pyvex.expr.IRExpr
    ) -> tuple[RichR[claripy.ast.BV], RichR[claripy.ast.BV]] | tuple[RichR[claripy.ast.FP], RichR[claripy.ast.FP]]:
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)
        assert type(r0) is type(r1)
        return r0, r1  # type: ignore

    @binop_handler
    def _handle_binop_Add(self, expr):
        r0, r1 = self._expr_pair(expr.args[0], expr.args[1])
        sum_ = r0.data + r1.data  # type: ignore

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(sum_, typevar=typeconsts.int_type(result_size), type_constraints=None)

        typevar = None
        if r0.typevar is not None and r1.data.concrete:
            typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.AddN(r1.data.concrete_value))

        tc: set[typevars.TypeConstraint] = set()
        if r0.typevar is not None and r1.typevar is not None:
            tc.add(typevars.Subtype(r0.typevar, r1.typevar))
        return RichR(
            sum_,
            typevar=typevar,
            type_constraints=tc,
        )

    @binop_handler
    def _handle_binop_Sub(self, expr):
        r0, r1 = self._expr_pair(expr.args[0], expr.args[1])
        diff = r0.data - r1.data  # type: ignore

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(diff, typevar=typeconsts.int_type(result_size), type_constraints=None)

        typevar = None
        if r0.typevar is not None and r1.data.concrete:
            typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.SubN(r1.data.concrete_value))

        return RichR(
            diff,
            typevar=typevar,
        )

    @binop_handler
    def _handle_binop_And(self, expr):
        r0 = self._expr_bv(expr.args[0])
        r1 = self._expr_bv(expr.args[1])

        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data & r1.data)

        if self.state.is_stack_address(r0.data):
            r = r0.data
        elif self.state.is_stack_address(r1.data):
            r = r1.data
        else:
            result_size = expr.result_size(self.tyenv)
            r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_Xor(self, expr):
        r0 = self._expr_bv(expr.args[0])
        r1 = self._expr_bv(expr.args[1])

        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data ^ r1.data)

        result_size = expr.result_size(self.tyenv)
        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_Or(self, expr):
        r0 = self._expr_bv(expr.args[0])
        r1 = self._expr_bv(expr.args[1])

        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data | r1.data)

        result_size = expr.result_size(self.tyenv)
        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_Not(self, expr):
        arg = expr.args[0]
        r0 = self._expr_bv(arg)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete:
            # constants
            return RichR(~r0.data)

        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_Mul(self, expr):
        r0, r1 = self._expr_pair(expr.args[0], expr.args[1])

        if r0.data.concrete and r1.data.concrete:
            # constants
            mul = r0.data * r1.data  # type: ignore
            return RichR(mul)

        result_size = expr.result_size(self.tyenv)
        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_MullS(self, expr):
        r0, r1 = self._expr_pair(expr.args[0], expr.args[1])

        if r0.data.concrete and r1.data.concrete:
            # constants
            xt = r0.data.size()
            mul = r0.data.sign_extend(xt) * r1.data.sign_extend(xt)  # type: ignore
            return RichR(mul)

        result_size = expr.result_size(self.tyenv)
        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_MullU(self, expr):
        r0, r1 = self._expr_pair(expr.args[0], expr.args[1])

        if r0.data.concrete and r1.data.concrete:
            # constants
            xt = r0.data.size()
            mul = r0.data.zero_extend(xt) * r1.data.zero_extend(xt)  # type: ignore
            return RichR(mul)

        result_size = expr.result_size(self.tyenv)
        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_DivMod(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        if r0.data.concrete and r1.data.concrete:
            # constants
            try:
                signed = "U" in expr.op  # Iop_DivModU64to32 vs Iop_DivMod
                from_size = r0.data.size()
                to_size = r1.data.size()
                if signed:
                    quotient = r0.data.SDiv(claripy.SignExt(from_size - to_size, r1.data))
                    remainder = r0.data.SMod(claripy.SignExt(from_size - to_size, r1.data))
                    quotient_size = to_size
                    remainder_size = to_size
                    result = claripy.Concat(
                        claripy.Extract(remainder_size - 1, 0, remainder),
                        claripy.Extract(quotient_size - 1, 0, quotient),
                    )
                else:
                    quotient = r0.data // claripy.ZeroExt(from_size - to_size, r1.data)
                    remainder = r0.data % claripy.ZeroExt(from_size - to_size, r1.data)
                    quotient_size = to_size
                    remainder_size = to_size
                    result = claripy.Concat(
                        claripy.Extract(remainder_size - 1, 0, remainder),
                        claripy.Extract(quotient_size - 1, 0, quotient),
                    )

                return RichR(result)
            except ZeroDivisionError:
                pass

        result_size = expr.result_size(self.tyenv)
        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_Div(self, expr):
        r0, r1 = self._expr_pair(expr.args[0], expr.args[1])

        if r0.data.concrete and r1.data.concrete:
            # constants
            try:
                div = r0.data / r1.data  # type: ignore
                return RichR(div)
            except ZeroDivisionError:
                pass

        result_size = expr.result_size(self.tyenv)
        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_Mod(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete and r1.data.concrete_value != 0:
            # constants
            try:
                if result_size != r1.data.size():
                    remainder = r0.data.SMod(claripy.SignExt(result_size - r1.data.size(), r1.data))
                else:
                    remainder = r0.data.SMod(r1.data)
                return RichR(remainder)
            except ZeroDivisionError:
                pass

        r = self.state.top(result_size)
        return RichR(r)

    @binop_handler
    def _handle_binop_Shr(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(
                claripy.LShR(r0.data, r1.data.concrete_value),
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(result_size)
        return RichR(
            r,
            typevar=r0.typevar,
        )

    @binop_handler
    def _handle_binop_Sar(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(
                r0.data >> r1.data.concrete_value,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(result_size)
        return RichR(r, typevar=r0.typevar)

    @binop_handler
    def _handle_binop_Shl(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(
                r0.data << r1.data.concrete_value,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(result_size)
        return RichR(
            r,
            typevar=r0.typevar,
        )

    @binop_handler
    def _handle_binop_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        self._expr(arg0)
        self._expr(arg1)

        return RichR(self.state.top(1))

    _handle_binop_CmpNE = _handle_binop_CmpEQ
    _handle_binop_CmpLE = _handle_binop_CmpEQ
    _handle_binop_CmpLT = _handle_binop_CmpEQ
    _handle_binop_CmpGE = _handle_binop_CmpEQ
    _handle_binop_CmpGT = _handle_binop_CmpEQ

    def _handle_ExpCmpNE64(self, expr):
        _, _ = self._expr(expr.args[0]), self._expr(expr.args[1])
        return RichR(self.state.top(expr.result_size(self.tyenv)))

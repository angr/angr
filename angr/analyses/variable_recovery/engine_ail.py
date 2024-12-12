# pylint:disable=arguments-differ,invalid-unary-operand-type
from __future__ import annotations
from typing import TYPE_CHECKING, cast
import logging

import ailment
import claripy
from unique_log_filter import UniqueLogFilter

from angr.engines.light.engine import SimEngineNostmtAIL
from angr.procedures import SIM_LIBRARIES, SIM_TYPE_COLLECTIONS
from angr.utils.constants import MAX_POINTSTO_BITS
from angr.sim_type import SimTypeFunction, dereference_simtype
from angr.analyses.typehoon import typeconsts, typevars
from angr.analyses.typehoon.lifter import TypeLifter
from .engine_base import SimEngineVRBase, RichR

if TYPE_CHECKING:
    pass


l = logging.getLogger(name=__name__)
l.addFilter(UniqueLogFilter())


class SimEngineVRAIL(
    SimEngineNostmtAIL["VariableRecoveryFastState", RichR[claripy.ast.BV | claripy.ast.FP], None, None],
    SimEngineVRBase["VariableRecoveryFastState", ailment.Block],
):
    """
    The engine for variable recovery on AIL.
    """

    def __init__(self, *args, call_info=None, vvar_to_vvar: dict[int, int] | None, **kwargs):
        super().__init__(*args, **kwargs)

        self._reference_spoffset: bool = False
        self.call_info = call_info or {}
        self.vvar_to_vvar = vvar_to_vvar

    def _mapped_vvarid(self, vvar_id: int) -> int | None:
        if self.vvar_to_vvar is not None and vvar_id in self.vvar_to_vvar:
            return self.vvar_to_vvar[vvar_id]
        return None

    def _process_block_end(self, block, stmt_data, whitelist):
        pass

    # Statement handlers

    def _handle_stmt_Assignment(self, stmt):
        dst_type = type(stmt.dst)

        if dst_type is ailment.Expr.Register:
            offset = stmt.dst.reg_offset
            data = self._expr(stmt.src)
            size = stmt.src.bits // 8

            if hasattr(stmt.dst, "write_size") and stmt.dst.write_size > size:
                # zero-fill this register
                self._assign_to_register(
                    offset, RichR(self.state.top(stmt.dst.write_size * 8)), stmt.dst.write_size, create_variable=False
                )

            self._assign_to_register(offset, data, size, src=stmt.src, dst=stmt.dst)

        elif dst_type is ailment.Expr.Tmp:
            # simply write to self.tmps
            data = self._expr(stmt.src)
            if data is None:
                return

            self.tmps[stmt.dst.tmp_idx] = data

        elif dst_type is ailment.Expr.VirtualVariable:
            data = self._expr(stmt.src)
            self._assign_to_vvar(
                stmt.dst, data, src=stmt.src, dst=stmt.dst, vvar_id=self._mapped_vvarid(stmt.dst.varid)
            )

            if stmt.dst.was_stack and isinstance(stmt.dst.stack_offset, int):
                # store it to the stack region in case it's directly referenced later
                self._store(
                    RichR(self.state.stack_address(stmt.dst.stack_offset)),
                    data,
                    stmt.dst.bits // self.arch.byte_width,
                    stmt=stmt,
                )

        else:
            l.warning("Unsupported dst type %s.", dst_type)

    def _handle_stmt_Store(self, stmt: ailment.Stmt.Store):
        addr_r = self._expr_bv(stmt.addr)
        data = self._expr(stmt.data)
        size = stmt.size
        self._store(addr_r, data, size, stmt=stmt)

    def _handle_stmt_Jump(self, stmt):
        pass

    def _handle_stmt_ConditionalJump(self, stmt):
        self._expr(stmt.condition)

    def _handle_expr_Tmp(self, expr):
        try:
            return self.tmps[expr.tmp_idx]
        except KeyError:
            return self._top(expr.bits)

    def _handle_expr_MultiStatementExpression(self, expr):
        for stmt in expr.statements:
            self._stmt(stmt)
        return self._expr(expr.expr)

    def _handle_expr_Call(self, expr):
        target = expr.target
        args = []
        if expr.args:
            for arg in expr.args:
                self._reference_spoffset = True
                richr = self._expr(arg)
                self._reference_spoffset = False
                args.append(richr)

        ret_expr_bits = expr.bits

        if isinstance(target, ailment.Expr.Expression) and not isinstance(
            target, (ailment.Expr.Const, ailment.Expr.DirtyExpression)
        ):
            # this is a dynamically calculated call target
            target_expr = self._expr(target)
            funcaddr_typevar = target_expr.typevar
            assert funcaddr_typevar is not None
            load_typevar = self._create_access_typevar(funcaddr_typevar, False, self.arch.bytes, 0)
            self.state.add_type_constraint(typevars.Subtype(funcaddr_typevar, load_typevar))

        # discover the prototype
        prototype: SimTypeFunction | None = None
        prototype_libname: str | None = None
        if expr.prototype is not None:
            prototype = expr.prototype
        if isinstance(expr.target, ailment.Expr.Const):
            func_addr = expr.target.value
            if isinstance(func_addr, self.kb.functions.address_types) and func_addr in self.kb.functions:
                func = self.kb.functions[func_addr]
                if prototype is None:
                    prototype = func.prototype
                prototype_libname = func.prototype_libname

        # dump the type of the return value
        ret_ty = typevars.TypeVariable() if prototype is not None else typevars.TypeVariable()
        if isinstance(ret_ty, typeconsts.BottomType):
            ret_ty = typevars.TypeVariable()

        if prototype is not None and args:
            # add type constraints

            type_collections = []
            if prototype_libname is not None:
                prototype_lib = SIM_LIBRARIES[prototype_libname]
                if prototype_lib.type_collection_names:
                    for typelib_name in prototype_lib.type_collection_names:
                        type_collections.append(SIM_TYPE_COLLECTIONS[typelib_name])

            for arg, arg_type in zip(args, prototype.args):
                if arg.typevar is not None:
                    arg_type = dereference_simtype(arg_type, type_collections).with_arch(arg_type._arch)
                    arg_ty = TypeLifter(self.arch.bits).lift(arg_type)
                    type_constraint = typevars.Subtype(arg.typevar, arg_ty)
                    self.state.add_type_constraint(type_constraint)

        return RichR(self.state.top(ret_expr_bits), typevar=ret_ty)

    def _handle_stmt_Call(self, stmt):
        target = stmt.target
        args = []
        if stmt.args:
            for arg in stmt.args:
                self._reference_spoffset = True
                richr = self._expr(arg)
                self._reference_spoffset = False
                args.append(richr)

        ret_expr_bits = self.state.arch.bits
        create_variable = True

        # this is a call statement. we need to update the return value register later
        ret_expr = stmt.ret_expr
        if ret_expr is not None:
            if ret_expr.category == ailment.Expr.VirtualVariableCategory.REGISTER:
                ret_expr_bits = ret_expr.bits
        else:
            # the return expression is not used, so we treat this call as not returning anything
            create_variable = False

        if isinstance(target, ailment.Expr.Expression) and not isinstance(
            target, (ailment.Expr.Const, ailment.Expr.DirtyExpression)
        ):
            # this is a dynamically calculated call target
            target_expr = self._expr(target)
            funcaddr_typevar = target_expr.typevar
            assert funcaddr_typevar is not None
            load_typevar = self._create_access_typevar(funcaddr_typevar, False, self.arch.bytes, 0)
            self.state.add_type_constraint(typevars.Subtype(funcaddr_typevar, load_typevar))

        # discover the prototype
        prototype: SimTypeFunction | None = None
        prototype_libname: str | None = None
        if stmt.prototype is not None:
            prototype = stmt.prototype
        if isinstance(stmt.target, ailment.Expr.Const):
            func_addr = stmt.target.value
            if isinstance(func_addr, self.kb.functions.address_types) and func_addr in self.kb.functions:
                func = self.kb.functions[func_addr]
                if prototype is None:
                    prototype = func.prototype
                prototype_libname = func.prototype_libname

        # dump the type of the return value
        ret_ty = typevars.TypeVariable() if prototype is not None else typevars.TypeVariable()
        if isinstance(ret_ty, typeconsts.BottomType):
            ret_ty = typevars.TypeVariable()

        # TODO: Expose it as an option
        return_value_use_full_width_reg = True

        # update the return value register
        if isinstance(ret_expr, ailment.Expr.VirtualVariable):
            expr_bits = ret_expr_bits
            self._assign_to_vvar(
                ret_expr,
                RichR(self.state.top(expr_bits), typevar=ret_ty),
                dst=ret_expr,
                create_variable=create_variable,
                vvar_id=self._mapped_vvarid(ret_expr.varid),
            )
        elif isinstance(ret_expr, ailment.Expr.Register):
            l.warning("Left-over register found in call.ret_expr.")
            expr_bits = self.state.arch.bits if return_value_use_full_width_reg else ret_expr_bits
            self._assign_to_register(
                ret_expr.reg_offset,
                RichR(self.state.top(expr_bits), typevar=ret_ty),
                expr_bits // self.arch.byte_width,
                dst=ret_expr,
                create_variable=create_variable,
            )

        if prototype is not None and args:
            # add type constraints

            type_collections = []
            if prototype_libname is not None:
                prototype_lib = SIM_LIBRARIES[prototype_libname]
                if prototype_lib.type_collection_names:
                    for typelib_name in prototype_lib.type_collection_names:
                        type_collections.append(SIM_TYPE_COLLECTIONS[typelib_name])

            for arg, arg_type in zip(args, prototype.args):
                if arg.typevar is not None:
                    arg_type = dereference_simtype(arg_type, type_collections).with_arch(arg_type._arch)
                    arg_ty = TypeLifter(self.arch.bits).lift(arg_type)
                    type_constraint = typevars.Subtype(arg.typevar, arg_ty)
                    self.state.add_type_constraint(type_constraint)

    def _handle_stmt_Return(self, stmt):
        if stmt.ret_exprs:
            for ret_expr in stmt.ret_exprs:
                self._expr(ret_expr)

    def _handle_expr_DirtyExpression(self, expr: ailment.Expr.DirtyExpression) -> RichR:
        for op in expr.operands:
            self._expr(op)
        if expr.guard:
            self._expr(expr.guard)
        if expr.maddr:
            self._expr(expr.maddr)
        return RichR(self.state.top(expr.bits))

    def _handle_expr_VEXCCallExpression(self, expr: ailment.Expr.VEXCCallExpression) -> RichR:
        for op in expr.operands:
            self._expr(op)
        return RichR(self.state.top(expr.bits))

    # Expression handlers

    def _expr_bv(self, expr: ailment.expression.Expression) -> RichR[claripy.ast.BV]:
        result = self._expr(expr)
        assert isinstance(result.data, claripy.ast.BV)
        return cast(RichR[claripy.ast.BV], result)

    def _expr_fp(self, expr: ailment.expression.Expression) -> RichR[claripy.ast.FP]:
        result = self._expr(expr)
        assert isinstance(result.data, claripy.ast.FP)
        return cast(RichR[claripy.ast.FP], result)

    def _expr_pair(
        self, expr1: ailment.expression.Expression, expr2: ailment.expression.Expression
    ) -> tuple[RichR[claripy.ast.BV], RichR[claripy.ast.BV]] | tuple[RichR[claripy.ast.FP], RichR[claripy.ast.FP]]:
        result1 = self._expr(expr1)
        result2 = self._expr(expr2)
        assert type(result1.data) is type(result2.data)
        return result1, result2  # type: ignore

    def _handle_expr_Register(self, expr):
        offset = expr.reg_offset
        size = expr.bits // 8

        return self._read_from_register(offset, size, expr=expr)

    def _handle_expr_Load(self, expr):
        addr_r = self._expr_bv(expr.addr)
        size = expr.size

        return self._load(addr_r, size, expr=expr)

    def _handle_expr_VirtualVariable(self, expr: ailment.Expr.VirtualVariable):
        return self._read_from_vvar(expr, expr=expr, vvar_id=self._mapped_vvarid(expr.varid))

    def _handle_expr_Phi(self, expr: ailment.Expr.Phi):
        tvs = set()
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                r = self._read_from_vvar(vvar, expr=expr, vvar_id=self._mapped_vvarid(vvar.varid))
                if r.typevar is not None:
                    tvs.add(r.typevar)

        tv = typevars.TypeVariable()
        for tv_ in tvs:
            self.state.add_type_constraint(typevars.Subtype(tv, tv_))
        return RichR(self.state.top(expr.bits), typevar=tv)

    def _handle_expr_Const(self, expr: ailment.Expr.Const):
        if isinstance(expr.value, float):
            v = claripy.FPV(expr.value, claripy.FSORT_DOUBLE if expr.bits == 64 else claripy.FSORT_FLOAT).to_bv()
            ty = typeconsts.float_type(expr.bits)
        else:
            if self.project.loader.find_segment_containing(expr.value) is not None:
                r = self._load_from_global(expr.value, 1, expr=expr)
                ty = r.typevar
            elif expr.value == 0 and expr.bits == self.arch.bits:
                # this can be viewed as a NULL
                ty = (
                    typeconsts.Pointer64(typeconsts.TopType())
                    if self.arch.bits == 64
                    else typeconsts.Pointer32(typeconsts.TopType())
                )
            else:
                ty = typeconsts.int_type(expr.bits)
            v = claripy.BVV(expr.value, expr.bits)
        r = RichR(v, typevar=ty)
        codeloc = self._codeloc()
        self._ensure_variable_existence(r, codeloc)
        self._reference(r, codeloc)
        return r

    def _handle_expr_Convert(self, expr: ailment.Expr.Convert):
        r = self._expr(expr.operand)
        typevar = None
        if r.typevar is not None:
            if isinstance(r.typevar, typevars.DerivedTypeVariable) and isinstance(
                r.typevar.one_label, typevars.ConvertTo
            ):
                # there is already a conversion - overwrite it
                if not isinstance(r.typevar.type_var, typeconsts.TypeConstant):
                    typevar = typevars.DerivedTypeVariable(r.typevar.type_var, typevars.ConvertTo(expr.to_bits))
            else:
                if not isinstance(r.typevar, typeconsts.TypeConstant):
                    typevar = typevars.DerivedTypeVariable(r.typevar, typevars.ConvertTo(expr.to_bits))

        return RichR(self.state.top(expr.to_bits), typevar=typevar)

    def _handle_expr_Reinterpret(self, expr: ailment.Expr.Reinterpret):
        r = self._expr(expr.operand)
        typevar = None
        if r.typevar is not None:
            if isinstance(r.typevar, typevars.DerivedTypeVariable) and isinstance(
                r.typevar.one_label, typevars.ReinterpretAs
            ):
                # there is already a reinterpretas - overwrite it
                typevar = typevars.DerivedTypeVariable(
                    r.typevar.type_var, typevars.ReinterpretAs(expr.to_type, expr.to_bits)
                )
            else:
                typevar = typevars.DerivedTypeVariable(r.typevar, typevars.ReinterpretAs(expr.to_type, expr.to_bits))

        return RichR(self.state.top(expr.to_bits), typevar=typevar)

    def _handle_expr_StackBaseOffset(self, expr: ailment.Expr.StackBaseOffset):
        ref_typevar = self.state.stack_offset_typevars.get(expr.offset, None)

        if ref_typevar is None:
            # allocate a new type variable
            ref_typevar = typevars.TypeVariable()
            self.state.stack_offset_typevars[expr.offset] = ref_typevar

        value_v = self.state.stack_address(expr.offset)
        richr = RichR(value_v, typevar=ref_typevar)
        codeloc = self._codeloc()
        var_and_offsets = self._ensure_variable_existence(richr, codeloc, src_expr=expr)
        if self._reference_spoffset:
            self._reference(richr, codeloc, src=expr)
        for var, off_in_var in var_and_offsets:
            if self.state.typevars.has_type_variable_for(var, codeloc):
                var_typevar = self.state.typevars.get_type_variable(var, codeloc)
                load_typevar = self._create_access_typevar(
                    ref_typevar, False, MAX_POINTSTO_BITS // 8, 0 if off_in_var is None else off_in_var
                )
                type_constraint = typevars.Subtype(var_typevar, load_typevar)
                self.state.add_type_constraint(type_constraint)

        return richr

    def _handle_expr_BasePointerOffset(self, expr):
        # TODO
        return self._top(expr.bits)

    def _handle_expr_ITE(self, expr: ailment.Expr.ITE):
        self._expr(expr.cond)  # cond
        self._expr(expr.iftrue)  # r0
        self._expr(expr.iffalse)  # r1

        return RichR(self.state.top(expr.bits))

    def _handle_binop_Add(self, expr):
        arg0, arg1 = expr.operands
        r0, r1 = self._expr_pair(arg0, arg1)
        compute = r0.data + r1.data  # type: ignore

        type_constraints = set()
        # create a new type variable and add constraints accordingly
        r0_typevar = r0.typevar if r0.typevar is not None else typevars.TypeVariable()

        if r1.data.concrete:
            # addition with constants. create a derived type variable
            typevar = typevars.DerivedTypeVariable(r0_typevar, typevars.AddN(r1.data.concrete_value))
        elif r1.typevar is not None:
            typevar = typevars.TypeVariable()
            type_constraints.add(typevars.Add(r0_typevar, r1.typevar, typevar))
        else:
            typevar = None

        return RichR(compute, typevar=typevar, type_constraints=type_constraints)

    def _handle_binop_Sub(self, expr):
        arg0, arg1 = expr.operands
        r0, r1 = self._expr_pair(arg0, arg1)
        compute = r0.data - r1.data  # type: ignore

        type_constraints = set()
        if r0.typevar is not None and r1.data.concrete:
            typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.SubN(r1.data.concrete_value))
        else:
            typevar = typevars.TypeVariable()
            if r0.typevar is not None and r1.typevar is not None:
                type_constraints.add(typevars.Sub(r0.typevar, r1.typevar, typevar))

        return RichR(
            compute,
            typevar=typevar,
            type_constraints=type_constraints,
        )

    def _handle_binop_Mul(self, expr):
        arg0, arg1 = expr.operands
        r0, r1 = self._expr_pair(arg0, arg1)

        result_size = arg0.bits
        if r0.data.concrete or r1.data.concrete:
            # constants
            result_size = arg0.bits
            compute = r0.data * r1.data  # type: ignore
            return RichR(compute, typevar=typeconsts.int_type(result_size), type_constraints=None)

        r = self.state.top(expr.bits)
        return RichR(
            r,
            typevar=r0.typevar,
        )

    def _handle_binop_Mull(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        if r0.data.concrete and r1.data.concrete:
            # constants
            result_size = expr.bits
            if r0.data.size() < result_size:
                if expr.signed:
                    r0.data = claripy.SignExt(result_size - r0.data.size(), r0.data)
                else:
                    r0.data = claripy.ZeroExt(result_size - r0.data.size(), r0.data)
            if r1.data.size() < result_size:
                if expr.signed:
                    r1.data = claripy.SignExt(result_size - r1.data.size(), r1.data)
                else:
                    r1.data = claripy.ZeroExt(result_size - r1.data.size(), r1.data)
            return RichR(r0.data * r1.data, typevar=typeconsts.int_type(result_size), type_constraints=None)

        r = self.state.top(expr.bits)
        return RichR(
            r,
            typevar=r0.typevar,  # FIXME: the size is probably changed
        )

    def _handle_binop_Div(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)
        from_size = expr.bits
        to_size = r1.bits

        if expr.floating_point:
            quotient = self.state.top(to_size)
        else:
            if (r1.data == 0).is_true():
                quotient = self.state.top(to_size)
            elif expr.signed:
                quotient = claripy.SDiv(r0.data, claripy.SignExt(from_size - to_size, r1.data))
            else:
                quotient = r0.data // claripy.ZeroExt(from_size - to_size, r1.data)

        return RichR(
            quotient,
            # | typevar=r0.typevar,  # FIXME: Handle typevars for Div
        )

    def _handle_binop_Mod(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)
        result_size = expr.bits

        if expr.floating_point:
            remainder = self.state.top(result_size)
        else:
            if (r1.data == 0).is_true():
                remainder = self.state.top(result_size)
            elif expr.signed:
                remainder = r0.data.SMod(r1.data)
            else:
                remainder = r0.data % r1.data

        # truncation if necessary
        if remainder.size() > result_size:
            remainder = claripy.Extract(result_size - 1, 0, remainder)

        return RichR(
            remainder,
            # | typevar=r0.typevar,  # FIXME: Handle typevars for Mod
        )

    def _handle_binop_Xor(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        if r0.data.concrete and r1.data.concrete:
            # constants
            result_size = arg0.bits
            return RichR(r0.data ^ r1.data, typevar=typeconsts.int_type(result_size), type_constraints=None)

        r = self.state.top(expr.bits)
        return RichR(
            r,
            typevar=r0.typevar,
        )

    def _handle_binop_Shl(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)
        result_size = arg0.bits

        if not r1.data.concrete:
            # we don't support symbolic shiftamount
            r = self.state.top(result_size)
            return RichR(
                r,
                typevar=r0.typevar,
            )

        shiftamount = r1.data.concrete_value
        return RichR(r0.data << shiftamount, typevar=typeconsts.int_type(result_size), type_constraints=None)

    def _handle_binop_Shr(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)
        result_size = arg0.bits

        if not r1.data.concrete:
            # we don't support symbolic shiftamount
            r = self.state.top(result_size)
            return RichR(
                r,
                typevar=r0.typevar,
            )

        shiftamount = r1.data.concrete_value

        return RichR(
            claripy.LShR(r0.data, shiftamount), typevar=typeconsts.int_type(result_size), type_constraints=None
        )

    def _handle_binop_Sal(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)
        result_size = arg0.bits

        if not r1.data.concrete:
            # we don't support symbolic shiftamount
            r = self.state.top(result_size)
            return RichR(
                r,
                typevar=r0.typevar,
            )

        shiftamount = r1.data.concrete_value

        return RichR(r0.data << shiftamount, typevar=typeconsts.int_type(result_size), type_constraints=None)

    def _handle_binop_Sar(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)
        result_size = arg0.bits

        if not r1.data.concrete:
            # we don't support symbolic shiftamount
            r = self.state.top(result_size)
            return RichR(
                r,
                typevar=r0.typevar,
            )

        shiftamount = r1.data.concrete_value

        return RichR(r0.data >> shiftamount, typevar=typeconsts.int_type(result_size), type_constraints=None)

    def _handle_binop_And(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        result_size = arg0.bits
        if r0.data.concrete and r1.data.concrete:
            return RichR(
                r0.data & r1.data,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(expr.bits)
        return RichR(r, typevar=typeconsts.int_type(result_size))

    def _handle_binop_Or(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        r1 = self._expr_bv(arg1)

        result_size = arg0.bits
        if r0.data.concrete and r1.data.concrete:
            return RichR(
                r0.data | r1.data,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(expr.bits)
        return RichR(r, typevar=typeconsts.int_type(result_size))

    def _handle_binop_LogicalAnd(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        _ = self._expr_bv(arg1)
        r = self.state.top(expr.bits)
        return RichR(r, typevar=r0.typevar)

    def _handle_binop_LogicalOr(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        _ = self._expr_bv(arg1)
        r = self.state.top(expr.bits)
        return RichR(r, typevar=r0.typevar)

    def _handle_binop_LogicalXor(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        _ = self._expr_bv(arg1)
        r = self.state.top(expr.bits)
        return RichR(r, typevar=r0.typevar)

    def _handle_binop_Rol(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        _ = self._expr_bv(arg1)
        result_size = arg0.bits

        r = self.state.top(result_size)
        return RichR(r, typevar=r0.typevar)

    def _handle_binop_Ror(self, expr):
        arg0, arg1 = expr.operands

        r0 = self._expr_bv(arg0)
        _ = self._expr_bv(arg1)
        result_size = arg0.bits

        r = self.state.top(result_size)
        return RichR(r, typevar=r0.typevar)

    def _handle_binop_Concat(self, expr):
        arg0, arg1 = expr.operands

        _ = self._expr_bv(arg0)
        _ = self._expr_bv(arg1)

        # TODO: Model the operation. Don't lose type constraints
        return RichR(self.state.top(expr.bits))

    def _handle_binop_Default(self, expr):
        arg0, arg1 = expr.operands

        self._expr(arg0)
        self._expr(arg1)

        return RichR(self.state.top(expr.bits))

    _handle_binop_AddF = _handle_binop_Default
    _handle_binop_SubF = _handle_binop_Default
    _handle_binop_SubV = _handle_binop_Default
    _handle_binop_MulF = _handle_binop_Default
    _handle_binop_DivF = _handle_binop_Default
    _handle_binop_DivV = _handle_binop_Default
    _handle_binop_AddV = _handle_binop_Default
    _handle_binop_MulV = _handle_binop_Default
    _handle_binop_MulHiV = _handle_binop_Default
    _handle_binop_Carry = _handle_binop_Default
    _handle_binop_Borrow = _handle_binop_Default
    _handle_binop_SCarry = _handle_binop_Default
    _handle_binop_SBorrow = _handle_binop_Default
    _handle_binop_InterleaveLOV = _handle_binop_Default
    _handle_binop_InterleaveHIV = _handle_binop_Default
    _handle_binop_CasCmpEQ = _handle_binop_Default
    _handle_binop_CasCmpNE = _handle_binop_Default
    _handle_binop_ExpCmpNE = _handle_binop_Default
    _handle_binop_SarNV = _handle_binop_Default
    _handle_binop_ShrNV = _handle_binop_Default
    _handle_binop_ShlNV = _handle_binop_Default
    _handle_binop_PermV = _handle_binop_Default
    _handle_binop_Set = _handle_binop_Default
    _handle_binop_MaxV = _handle_binop_Default
    _handle_binop_MinV = _handle_binop_Default
    _handle_binop_QAddV = _handle_binop_Default
    _handle_binop_QNarrowBinV = _handle_binop_Default
    _handle_binop_CmpEQ = _handle_binop_Default
    _handle_binop_CmpNE = _handle_binop_Default
    _handle_binop_CmpLT = _handle_binop_Default
    _handle_binop_CmpLE = _handle_binop_Default
    _handle_binop_CmpGT = _handle_binop_Default
    _handle_binop_CmpGE = _handle_binop_Default
    _handle_binop_CmpEQV = _handle_binop_Default
    _handle_binop_CmpNEV = _handle_binop_Default
    _handle_binop_CmpGEV = _handle_binop_Default
    _handle_binop_CmpGTV = _handle_binop_Default
    _handle_binop_CmpLEV = _handle_binop_Default
    _handle_binop_CmpLTV = _handle_binop_Default
    _handle_binop_CmpF = _handle_binop_Default

    def _handle_unop_Not(self, expr):
        arg = expr.operands[0]
        expr = self._expr_bv(arg)

        result_size = arg.bits

        if expr.data.concrete:
            return RichR(
                ~expr.data,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(result_size)
        return RichR(r, typevar=expr.typevar)

    def _handle_unop_Neg(self, expr):
        arg = expr.operands[0]
        expr = self._expr_bv(arg)

        result_size = arg.bits

        if expr.data.concrete:
            return RichR(
                -expr.data,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(result_size)
        return RichR(r, typevar=expr.typevar)

    def _handle_unop_BitwiseNeg(self, expr):
        arg = expr.operands[0]
        expr = self._expr_bv(arg)

        result_size = arg.bits

        if expr.data.concrete:
            return RichR(
                ~expr.data,
                typevar=typeconsts.int_type(result_size),
                type_constraints=None,
            )

        r = self.state.top(result_size)
        return RichR(r, typevar=expr.typevar)

    def _handle_unop_Default(self, expr):
        self._expr(expr.operands[0])
        return RichR(self.state.top(expr.bits))

    _handle_unop_Reference = _handle_unop_Default
    _handle_unop_Dereference = _handle_unop_Default
    _handle_unop_Clz = _handle_unop_Default
    _handle_unop_Ctz = _handle_unop_Default
    _handle_unop_GetMSBs = _handle_unop_Default
    _handle_unop_unpack = _handle_unop_Default
    _handle_unop_Sqrt = _handle_unop_Default
    _handle_unop_RSqrtEst = _handle_unop_Default
